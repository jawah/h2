use httlib_hpack::{Decoder as InternalDecoder, Encoder as InternalEncoder};
use pyo3::exceptions::PyException;
use pyo3::types::{PyList, PyTuple};
use pyo3::{prelude::*, types::PyBytes, BoundObject};

pyo3::create_exception!(_hazmat, HPACKError, PyException);
pyo3::create_exception!(_hazmat, OversizedHeaderListError, PyException);

#[pyclass(module = "jh2._hazmat")]
pub struct Encoder {
    inner: InternalEncoder<'static>,
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
        }
    }

    #[pyo3(signature = (headers, huffman=None))]
    pub fn encode<'a>(
        &mut self,
        py: Python<'a>,
        headers: Vec<(Bound<'_, PyBytes>, Bound<'_, PyBytes>, bool)>,
        huffman: Option<bool>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut flags = InternalEncoder::BEST_FORMAT;

        if huffman.is_none() || huffman.unwrap() {
            flags |= InternalEncoder::HUFFMAN_VALUE;
        }

        let mut dst = Vec::new();

        for (header, value, sensitive) in headers.iter() {
            let mut header_flags: u8 = flags;

            if *sensitive {
                header_flags |= InternalEncoder::NEVER_INDEXED;
            } else {
                header_flags |= InternalEncoder::WITH_INDEXING;
            }

            let enc_res = self.inner.encode(
                (
                    header.as_bytes().to_vec(),
                    value.as_bytes().to_vec(),
                    header_flags,
                ),
                &mut dst,
            );

            if enc_res.is_err() {
                return Err(HPACKError::new_err("operation failed"));
            }
        }

        Ok(PyBytes::new(py, dst.as_slice()))
    }

    #[pyo3(signature = (header, sensitive, huffman=None))]
    pub fn add<'a>(
        &mut self,
        py: Python<'a>,
        header: (Bound<'_, PyBytes>, Bound<'_, PyBytes>),
        sensitive: bool,
        huffman: Option<bool>,
    ) -> PyResult<Bound<'a, PyBytes>> {
        let mut flags = InternalEncoder::BEST_FORMAT;

        if huffman.is_none() || huffman.unwrap() {
            flags |= InternalEncoder::HUFFMAN_VALUE;
        }

        if sensitive {
            flags |= InternalEncoder::NEVER_INDEXED;
        } else {
            flags |= InternalEncoder::WITH_INDEXING;
        }

        let mut dst = Vec::new();

        let enc_res = self.inner.encode(
            (
                header.0.as_bytes().to_vec(),
                header.1.as_bytes().to_vec(),
                flags,
            ),
            &mut dst,
        );

        if enc_res.is_err() {
            return Err(HPACKError::new_err("operation failed"));
        }

        Ok(PyBytes::new(py, dst.as_slice()))
    }

    #[getter]
    pub fn get_header_table_size(&mut self) -> u32 {
        self.inner.max_dynamic_size()
    }

    #[setter]
    pub fn set_header_table_size(&mut self, value: u32) -> PyResult<()> {
        let mut out = Vec::new();
        let res = self.inner.update_max_dynamic_size(value, &mut out);

        if res.is_err() {
            return Err(HPACKError::new_err("invalid header table size set"));
        }

        Ok(())
    }
}

#[pymethods]
impl Decoder {
    #[pyo3(signature = (max_header_list_size=None))]
    #[new]
    pub fn py_new(max_header_list_size: Option<u32>) -> Self {
        let mut max_hls: u32 = 65536;

        if max_header_list_size.is_some() {
            max_hls = max_header_list_size.unwrap();
        }

        Decoder {
            inner: InternalDecoder::with_dynamic_size(4096),
            max_header_list_size: max_hls,
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

        let mut total_mem = 0;

        loop {
            if buf.is_empty() {
                break;
            }

            let mut data = Vec::with_capacity(1);

            let dec_res = self.inner.decode_exact(&mut buf, &mut data);

            if dec_res.is_err() {
                return Err(HPACKError::new_err("operation failed"));
            }

            if !data.is_empty() {
                total_mem += data[0].0.len() + data[0].1.len();
                dst.append(&mut data);

                if total_mem as u32 >= self.max_header_list_size {
                    return Err(OversizedHeaderListError::new_err(
                        "attempt to DDoS hpack decoder detected",
                    ));
                }
            }
        }

        let res = PyList::empty(py);

        for (name, value, flags) in dst {
            let is_sensitive =
                flags & InternalDecoder::NEVER_INDEXED == InternalDecoder::NEVER_INDEXED;

            if raw.is_none() || raw.unwrap() {
                let _ = res.append(
                    PyTuple::new(
                        py,
                        [
                            PyBytes::new(py, &name)
                                .into_pyobject(py)
                                .unwrap()
                                .into_any(),
                            PyBytes::new(py, &value)
                                .into_pyobject(py)
                                .unwrap()
                                .into_any(),
                            is_sensitive
                                .into_pyobject(py)
                                .unwrap()
                                .into_bound()
                                .into_any(),
                        ],
                    )
                    .unwrap(),
                );
            } else {
                let _ = res.append(
                    PyTuple::new(
                        py,
                        [
                            std::str::from_utf8(&name)
                                .unwrap()
                                .into_pyobject(py)
                                .unwrap()
                                .into_any(),
                            std::str::from_utf8(&value)
                                .unwrap()
                                .into_pyobject(py)
                                .unwrap()
                                .into_any(),
                            is_sensitive
                                .into_pyobject(py)
                                .unwrap()
                                .into_bound()
                                .into_any(),
                        ],
                    )
                    .unwrap(),
                );
            }
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
