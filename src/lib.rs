use httlib_hpack::{Decoder as InternalDecoder, Encoder as InternalEncoder};
use pyo3::exceptions::PyException;
use pyo3::types::{PyList, PyTuple};
use pyo3::{prelude::*, types::PyBytes, BoundObject};

pyo3::create_exception!(_hazmat, HPACKError, PyException);
pyo3::create_exception!(_hazmat, OversizedHeaderListError, PyException);

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
            for (header, value, sensitive) in &headers {
                let mut header_flags: u8 = flags;

                if *sensitive {
                    header_flags |= InternalEncoder::NEVER_INDEXED;
                } else {
                    header_flags |= InternalEncoder::WITH_INDEXING;
                }

                self.inner
                    .encode((header.clone(), value.clone(), header_flags), &mut dst)
                    .map_err(|_| HPACKError::new_err("operation failed"))?;
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
                .encode((header.0.clone(), header.1.clone(), flags), &mut dst)
                .map_err(|_| HPACKError::new_err("operation failed"))
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
            .map_err(|_| HPACKError::new_err("invalid header table size set"))
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
                    .map_err(|_| HPACKError::new_err("operation failed"))?;

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

    Ok(())
}
