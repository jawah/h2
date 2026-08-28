use std::collections::VecDeque;

use httlib_hpack::{Decoder as InternalDecoder, Encoder as InternalEncoder};
use pyo3::class::{PyTraverseError, PyVisit};
use pyo3::exceptions::PyException;
use pyo3::types::{PyList, PyMemoryView, PyTuple};
use pyo3::{prelude::*, types::PyBytes, BoundObject};

pyo3::create_exception!(_hazmat, HPACKError, PyException);
pyo3::create_exception!(_hazmat, OversizedHeaderListError, PyException);

enum BytesChunkData {
    Bytes(Py<PyBytes>),
    MemoryView(Py<PyAny>),
}

struct BytesChunk {
    data: BytesChunkData,
    offset: usize,
    len: usize,
}

#[pyclass(module = "jh2._hazmat", name = "_BytesQueueBuffer")]
struct BytesQueueBuffer {
    chunks: VecDeque<BytesChunk>,
    size: usize,
}

#[pymethods]
impl BytesQueueBuffer {
    #[new]
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            size: 0,
        }
    }

    fn __len__(&self) -> usize {
        self.size
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for chunk in &self.chunks {
            match &chunk.data {
                BytesChunkData::Bytes(data) => visit.call(data)?,
                BytesChunkData::MemoryView(data) => visit.call(data)?,
            }
        }
        Ok(())
    }

    fn __clear__(&mut self) {
        self.chunks.clear();
        self.size = 0;
    }

    fn put(&mut self, data: &Bound<'_, PyAny>) -> PyResult<()> {
        let len = data.len()?;
        let data = if let Ok(data) = data.cast::<PyBytes>() {
            BytesChunkData::Bytes(data.clone().unbind())
        } else {
            data.cast::<PyMemoryView>()?;
            BytesChunkData::MemoryView(data.clone().unbind())
        };
        self.size += len;
        self.chunks.push_back(BytesChunk {
            data,
            offset: 0,
            len,
        });
        Ok(())
    }

    fn put_many(&mut self, chunks: &Bound<'_, PyAny>) -> PyResult<()> {
        for chunk in chunks.try_iter()? {
            let chunk = chunk?;
            if chunk.len()? != 0 {
                self.put(&chunk)?;
            }
        }
        Ok(())
    }

    fn get(&mut self, py: Python<'_>, n: isize) -> PyResult<Py<PyBytes>> {
        if n == 0 {
            return Ok(PyBytes::new(py, b"").unbind());
        }
        if self.chunks.is_empty() {
            return Err(pyo3::exceptions::PyRuntimeError::new_err("buffer is empty"));
        }
        if n < 0 {
            return Err(pyo3::exceptions::PyValueError::new_err("n should be > 0"));
        }

        while self
            .chunks
            .front()
            .is_some_and(|chunk| chunk.len == chunk.offset)
        {
            self.chunks.pop_front();
        }
        if self.chunks.is_empty() {
            return Ok(PyBytes::new(py, b"").unbind());
        }

        self.ensure_front_bytes(py)?;
        let requested = n as usize;
        if let Some(chunk) = self.chunks.front() {
            let chunk_len = chunk.len - chunk.offset;
            if chunk.offset == 0 && chunk_len == requested {
                self.size -= requested;
                let chunk = self.chunks.pop_front().unwrap();
                if let BytesChunkData::Bytes(data) = chunk.data {
                    return Ok(data);
                }
                unreachable!();
            }
        }

        let output_len = requested.min(self.size);
        let output = new_bytes_with(py, output_len, |output| {
            let mut written = 0;
            while written < output_len {
                self.ensure_front_bytes(py)?;
                let Some(chunk) = self.chunks.front() else {
                    break;
                };
                let BytesChunkData::Bytes(chunk_data) = &chunk.data else {
                    unreachable!();
                };
                let chunk_data = chunk_data.bind(py).as_bytes();
                let available = chunk.len - chunk.offset;
                if available == 0 {
                    self.chunks.pop_front();
                    continue;
                }

                let copied = available.min(output_len - written);
                output[written..written + copied]
                    .copy_from_slice(&chunk_data[chunk.offset..chunk.offset + copied]);
                written += copied;

                if copied == available {
                    self.chunks.pop_front();
                } else {
                    self.chunks.front_mut().unwrap().offset += copied;
                }
            }
            if written != output_len {
                return Err(pyo3::exceptions::PyRuntimeError::new_err(
                    "byte queue size invariant violated",
                ));
            }
            Ok(())
        })?;
        self.size -= output_len;
        while self
            .chunks
            .front()
            .is_some_and(|chunk| chunk.len == chunk.offset)
        {
            self.chunks.pop_front();
        }
        Ok(output.unbind())
    }

    fn ensure_front_bytes(&mut self, py: Python<'_>) -> PyResult<()> {
        let Some(chunk) = self.chunks.front_mut() else {
            return Ok(());
        };
        let BytesChunkData::MemoryView(data) = &chunk.data else {
            return Ok(());
        };

        let data = data
            .bind(py)
            .call_method0("tobytes")?
            .cast_into::<PyBytes>()?
            .unbind();
        chunk.data = BytesChunkData::Bytes(data);
        Ok(())
    }
}

fn new_bytes_with<'py>(
    py: Python<'py>,
    len: usize,
    fill: impl FnOnce(&mut [u8]) -> PyResult<()>,
) -> PyResult<Bound<'py, PyBytes>> {
    unsafe {
        let ptr = pyo3::ffi::PyBytes_FromStringAndSize(std::ptr::null(), len as isize);
        let bytes: Bound<'py, PyBytes> =
            Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked();
        let buffer = pyo3::ffi::PyBytes_AsString(ptr).cast::<u8>();
        fill(std::slice::from_raw_parts_mut(buffer, len))?;
        Ok(bytes)
    }
}

#[pyclass(module = "jh2._hazmat")]
pub struct Encoder {
    inner: InternalEncoder<'static>,
    pending_table_size_update: Vec<u8>,
}

#[pyclass(module = "jh2._hazmat")]
pub struct Decoder {
    inner: InternalDecoder<'static>,
    max_header_list_size: u32,
}

#[pymethods]
impl Encoder {
    #[new]
    pub fn py_new() -> Self {
        Encoder {
            inner: InternalEncoder::with_dynamic_size(4096),
            pending_table_size_update: Vec::new(),
        }
    }

    #[pyo3(signature = (headers, huffman=None))]
    pub fn encode<'a>(
        &mut self,
        py: Python<'a>,
        headers: Vec<(Vec<u8>, Vec<u8>, bool)>,
        huffman: Option<bool>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut flags = InternalEncoder::BEST_FORMAT;

        if huffman.unwrap_or(true) {
            flags |= InternalEncoder::HUFFMAN_VALUE;
        }

        // Prepend any pending table size update signal
        let mut dst = std::mem::take(&mut self.pending_table_size_update);

        py.detach(|| -> PyResult<()> {
            for (header, value, sensitive) in headers {
                let mut header_flags: u8 = flags;

                if sensitive {
                    header_flags |= InternalEncoder::NEVER_INDEXED;
                } else {
                    header_flags |= InternalEncoder::WITH_INDEXING;
                }

                self.inner
                    .encode((header, value, header_flags), &mut dst)
                    .map_err(|e| HPACKError::new_err(format!("encoder failure: {e:?}")))?;
            }
            Ok(())
        })?;

        Ok(PyBytes::new(py, dst.as_slice()))
    }

    #[pyo3(signature = (header, sensitive, huffman=None))]
    pub fn add<'a>(
        &mut self,
        py: Python<'a>,
        header: (Vec<u8>, Vec<u8>),
        sensitive: bool,
        huffman: Option<bool>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut flags = InternalEncoder::BEST_FORMAT;

        if huffman.unwrap_or(true) {
            flags |= InternalEncoder::HUFFMAN_VALUE;
        }

        if sensitive {
            flags |= InternalEncoder::NEVER_INDEXED;
        } else {
            flags |= InternalEncoder::WITH_INDEXING;
        }

        let mut dst = Vec::new();

        py.detach(|| {
            self.inner
                .encode((header.0, header.1, flags), &mut dst)
                .map_err(|e| HPACKError::new_err(format!("encoder failure: {e:?}")))
        })?;

        Ok(PyBytes::new(py, dst.as_slice()))
    }

    #[getter]
    pub fn get_header_table_size(&mut self) -> u32 {
        self.inner.max_dynamic_size()
    }

    #[setter]
    pub fn set_header_table_size(&mut self, value: u32) -> PyResult<()> {
        self.inner
            .update_max_dynamic_size(value, &mut self.pending_table_size_update)
            .map_err(|e| HPACKError::new_err(format!("invalid header table size set: {e:?}")))
    }
}

#[pymethods]
impl Decoder {
    #[pyo3(signature = (max_header_list_size=None))]
    #[new]
    pub fn py_new(max_header_list_size: Option<u32>) -> Self {
        Decoder {
            inner: InternalDecoder::with_dynamic_size(4096),
            max_header_list_size: max_header_list_size.unwrap_or(65536),
        }
    }

    #[pyo3(signature = (data, raw=None))]
    pub fn decode<'a>(
        &mut self,
        py: Python<'a>,
        data: Bound<'_, PyBytes>,
        raw: Option<bool>,
    ) -> PyResult<Bound<'a, PyList>> {
        let mut dst = Vec::new();
        let mut buf = data.as_bytes().to_vec();
        let max_header_list_size = self.max_header_list_size as usize;

        // Decode all headers in a single GIL-release block
        let decode_result: PyResult<()> = py.detach(|| {
            let mut total_mem: usize = 0;

            while !buf.is_empty() {
                let mut data = Vec::with_capacity(1);

                self.inner
                    .decode_exact(&mut buf, &mut data)
                    .map_err(|e| HPACKError::new_err(format!("decoder failure: {e:?}")))?;

                if !data.is_empty() {
                    total_mem += data[0].0.len() + data[0].1.len();
                    dst.append(&mut data);

                    if total_mem >= max_header_list_size {
                        return Err(OversizedHeaderListError::new_err(
                            "attempt to DDoS hpack decoder detected",
                        ));
                    }
                }
            }
            Ok(())
        });
        decode_result?;

        // Build the Python list from decoded headers (requires GIL)
        let res = PyList::empty(py);
        let return_raw = raw.unwrap_or(true);

        for (name, value, flags) in dst {
            let is_sensitive =
                flags & InternalDecoder::NEVER_INDEXED == InternalDecoder::NEVER_INDEXED;

            let tuple = if return_raw {
                PyTuple::new(
                    py,
                    [
                        PyBytes::new(py, &name).into_pyobject(py)?.into_any(),
                        PyBytes::new(py, &value).into_pyobject(py)?.into_any(),
                        is_sensitive.into_pyobject(py)?.into_bound().into_any(),
                    ],
                )?
            } else {
                let name_str = std::str::from_utf8(&name)
                    .map_err(|_| HPACKError::new_err("header name is not valid UTF-8"))?;
                let value_str = std::str::from_utf8(&value)
                    .map_err(|_| HPACKError::new_err("header value is not valid UTF-8"))?;

                PyTuple::new(
                    py,
                    [
                        name_str.into_pyobject(py)?.into_any(),
                        value_str.into_pyobject(py)?.into_any(),
                        is_sensitive.into_pyobject(py)?.into_bound().into_any(),
                    ],
                )?
            };

            res.append(tuple)?;
        }

        Ok(res)
    }

    #[getter]
    pub fn get_header_table_size(&self) -> u32 {
        self.inner.max_dynamic_size()
    }

    #[setter]
    pub fn set_header_table_size(&mut self, value: u32) {
        self.inner.set_max_dynamic_size(value);
    }

    // httlib_hpack does not expose the dynamic table current size
    #[getter]
    pub fn get_max_allowed_table_size(&self) -> u32 {
        self.inner.max_dynamic_size()
    }

    #[setter]
    pub fn set_max_allowed_table_size(&mut self, value: u32) {
        self.inner.set_max_dynamic_size(value);
    }

    #[getter]
    pub fn get_max_header_list_size(&self) -> u32 {
        self.max_header_list_size
    }

    #[setter]
    pub fn set_max_header_list_size(&mut self, value: u32) {
        self.max_header_list_size = value;
    }
}

#[pymodule(gil_used = false)]
fn _hazmat(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("HPACKError", py.get_type::<HPACKError>())?;
    m.add(
        "OversizedHeaderListError",
        py.get_type::<OversizedHeaderListError>(),
    )?;
    m.add_class::<Decoder>()?;
    m.add_class::<Encoder>()?;
    m.add_class::<BytesQueueBuffer>()?;

    Ok(())
}
