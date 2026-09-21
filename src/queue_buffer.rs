//! Buffer API path for GIL-enabled interpreters with the full API or abi3-py311.
//! Free-threaded builds use the Python-managed copying path in lib.rs.

use pyo3::{ffi, prelude::*, types::PyBytes};

use crate::{BytesChunkData, BytesQueueBuffer};

/// Acquire a temporary export at a stable stack address. The closure cannot
/// retain the descriptor. All callers hold the GIL and pass exact memoryviews.
pub(super) fn with_buffer<T>(
    data: &Bound<'_, PyAny>,
    use_buffer: impl FnOnce(&ffi::Py_buffer) -> PyResult<T>,
) -> PyResult<T> {
    struct Export(ffi::Py_buffer);

    impl Drop for Export {
        fn drop(&mut self) {
            // The Python attachment outlives this guard, including error paths.
            unsafe { ffi::PyBuffer_Release(&mut self.0) };
        }
    }

    let mut export = Export(ffi::Py_buffer::new());
    // Do not move export after acquiring it: buffer descriptors may contain
    // pointers into themselves. Its Drop runs in place after the closure.
    if unsafe { ffi::PyObject_GetBuffer(data.as_ptr(), &mut export.0, ffi::PyBUF_FULL_RO) } < 0 {
        return Err(PyErr::fetch(data.py()));
    }
    use_buffer(&export.0)
}

impl BytesQueueBuffer {
    pub(super) fn copy_output<'py>(
        &mut self,
        py: Python<'py>,
        output_len: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // Strided tobytes() can itself need a temporary contiguous allocation.
        // Flatten before allocating the output to avoid an extra live payload.
        // Ordinary bytes/contiguous-view queues skip this pass entirely.
        if self.strided_chunks != 0 {
            let mut remaining = output_len;
            for chunk in &mut self.chunks {
                if remaining == 0 {
                    break;
                }
                let copied = (chunk.len - chunk.offset).min(remaining);
                if copied != 0 {
                    if let BytesChunkData::MemoryView {
                        data,
                        contiguous: false,
                    } = &chunk.data
                    {
                        let data = data
                            .bind(py)
                            .call_method0(pyo3::intern!(py, "tobytes"))?
                            .cast_into::<PyBytes>()?;
                        chunk.data = BytesChunkData::Bytes(data.unbind());
                        self.strided_chunks -= 1;
                    }
                }
                remaining -= copied;
            }
        }
        // Allocate only the final output. It stays unpublished until every
        // byte is initialized; never form a Rust slice over unwritten memory.
        let output: Bound<'_, PyBytes> = unsafe {
            Bound::from_owned_ptr_or_err(
                py,
                ffi::PyBytes_FromStringAndSize(std::ptr::null(), output_len as isize),
            )?
            .cast_into_unchecked()
        };
        let destination = unsafe { ffi::PyBytes_AsString(output.as_ptr()).cast::<u8>() };
        let mut written = 0;
        for chunk in &mut self.chunks {
            if written == output_len {
                break;
            }
            let copied = (chunk.len - chunk.offset).min(output_len - written);
            if copied == 0 {
                continue;
            }
            match &chunk.data {
                BytesChunkData::Bytes(data) => {
                    let source = &data.bind(py).as_bytes()[chunk.offset..chunk.offset + copied];
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            source.as_ptr(),
                            destination.add(written),
                            copied,
                        );
                    }
                }
                BytesChunkData::MemoryView { data, .. } => {
                    with_buffer(data.bind(py), |buffer| {
                        // A temporary export pins the allocation during the copy
                        // and detects a released queued view. The GIL stays held;
                        // no Python calls occur between acquiring and reading it.
                        // Mutable storage is never exposed as a Rust reference.
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                buffer.buf.cast::<u8>().add(chunk.offset),
                                destination.add(written),
                                copied,
                            );
                        }
                        Ok(())
                    })?;
                }
            }
            written += copied;
        }
        if written != output_len {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "byte queue size invariant violated",
            ));
        }
        Ok(output)
    }
}
