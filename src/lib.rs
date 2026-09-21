use std::collections::VecDeque;

use httlib_hpack::{Decoder as InternalDecoder, Encoder as InternalEncoder};
use pyo3::class::{PyTraverseError, PyVisit};
use pyo3::exceptions::PyException;
#[cfg(not(queue_native_buffer))]
use pyo3::intern;
#[cfg(not(queue_native_buffer))]
use pyo3::types::PySlice;
use pyo3::types::{PyList, PyMemoryView, PyTuple};
use pyo3::{prelude::*, types::PyBytes, BoundObject, PyClassGuardMut};

#[cfg(any(queue_native_buffer, Py_GIL_DISABLED))]
mod queue_buffer;

pyo3::create_exception!(_hazmat, HPACKError, PyException);
pyo3::create_exception!(_hazmat, OversizedHeaderListError, PyException);

enum BytesChunkData {
    Bytes(Py<PyBytes>),
    MemoryView { data: Py<PyAny>, contiguous: bool },
}

struct BytesChunk {
    data: BytesChunkData,
    offset: usize,
    len: usize,
}

/// Keep objects which may run Python finalizers alive until the queue borrow ends.
/// One retired object fits inline; ordinary bytes never enter this collection.
#[derive(Default)]
enum RetiredChunks {
    #[default]
    Empty,
    One(Py<PyAny>),
    Many(Vec<Py<PyAny>>),
}

impl RetiredChunks {
    #[inline]
    fn push(&mut self, data: BytesChunkData, py: Python<'_>) {
        let data = match data {
            BytesChunkData::Bytes(data) => {
                if data.bind(py).is_exact_instance_of::<PyBytes>() {
                    return;
                }
                data.into_any()
            }
            BytesChunkData::MemoryView { data, .. } => data,
        };
        self.push_owner(data);
    }

    // Keep allocation and growth out of the ordinary-bytes release path.
    #[inline(never)]
    fn push_owner(&mut self, data: Py<PyAny>) {
        match self {
            Self::Empty => *self = Self::One(data),
            Self::One(_) => {
                let Self::One(first) = std::mem::take(self) else {
                    unreachable!()
                };
                let mut items = Vec::with_capacity(8);
                items.extend([first, data]);
                *self = Self::Many(items);
            }
            Self::Many(items) => items.push(data),
        }
    }

    fn release(self, py: Python<'_>) {
        // We already know this thread is attached. Release directly instead of
        // consulting PyO3's deferred-reference machinery for each owner.
        match self {
            Self::Empty => {}
            Self::One(data) => data.drop_ref(py),
            Self::Many(items) => {
                for data in items {
                    data.drop_ref(py);
                }
            }
        }
    }
}

#[pyclass(module = "jh2._hazmat", name = "_BytesQueueBuffer")]
struct BytesQueueBuffer {
    chunks: VecDeque<BytesChunk>,
    size: usize,
    #[cfg(queue_native_buffer)]
    strided_chunks: usize,
}

#[pymethods]
impl BytesQueueBuffer {
    #[new]
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            size: 0,
            #[cfg(queue_native_buffer)]
            strided_chunks: 0,
        }
    }

    fn __len__(&self) -> usize {
        self.size
    }

    fn __traverse__(&self, visit: PyVisit<'_>) -> Result<(), PyTraverseError> {
        for chunk in &self.chunks {
            match &chunk.data {
                BytesChunkData::Bytes(data) => visit.call(data)?,
                BytesChunkData::MemoryView { data, .. } => visit.call(data)?,
            }
        }
        Ok(())
    }

    fn __clear__(mut slf: PyClassGuardMut<'_, Self>) {
        slf.size = 0;
        #[cfg(queue_native_buffer)]
        {
            slf.strided_chunks = 0;
        }
        let chunks = std::mem::take(&mut slf.chunks);
        drop(slf);
        drop(chunks);
    }

    fn put(slf: &Bound<'_, Self>, data: &Bound<'_, PyAny>) -> PyResult<()> {
        if let Some(chunk) = Self::prepare_chunk(data, false)? {
            slf.extract::<PyClassGuardMut<'_, Self>>()?.enqueue(chunk);
        }
        Ok(())
    }

    fn put_many(slf: &Bound<'_, Self>, chunks: &Bound<'_, PyAny>) -> PyResult<()> {
        // Advancing exact built-in sequence iterators cannot call Python.
        // Use the list iterator itself to preserve its mutation semantics.
        if chunks.is_exact_instance_of::<PyList>() || chunks.is_exact_instance_of::<PyTuple>() {
            return Self::enqueue_many::<true>(slf, chunks.try_iter()?);
        }
        Self::enqueue_many::<false>(slf, chunks.try_iter()?)
    }

    fn get(slf: PyClassGuardMut<'_, Self>, py: Python<'_>, n: isize) -> PyResult<Py<PyBytes>> {
        let mut retired = RetiredChunks::default();
        // This declaration order also releases the borrow first during unwinding.
        let mut queue = slf;
        let result = queue.read(py, n, &mut retired);
        // Also release the borrow before running finalizers on error paths.
        drop(queue);
        retired.release(py);
        result
    }
}

impl BytesQueueBuffer {
    fn enqueue_many<'py, const BUILTIN: bool>(
        slf: &Bound<'_, Self>,
        chunks: impl Iterator<Item = PyResult<Bound<'py, PyAny>>>,
    ) -> PyResult<()> {
        // Only exact bytes from built-in iterators can share a borrow. Preparing
        // any other input, or advancing a user iterator, happens without one.
        let mut queue: Option<PyClassGuardMut<'_, Self>> = None;
        for data in chunks {
            let data = data?;
            if BUILTIN && data.is_exact_instance_of::<PyBytes>() {
                if queue.is_none() {
                    queue = Some(slf.extract()?);
                }
                // The exact-type check above also excludes finalizers on empty
                // items. No Python allocation or callback occurs in this path.
                let data = unsafe { data.cast_into_unchecked::<PyBytes>() };
                let len = data.as_bytes().len();
                if len != 0 {
                    queue.as_mut().unwrap().enqueue(BytesChunk {
                        data: BytesChunkData::Bytes(data.unbind()),
                        offset: 0,
                        len,
                    });
                }
            } else {
                drop(queue.take());
                if let Some(chunk) = Self::prepare_chunk(&data, true)? {
                    slf.extract::<PyClassGuardMut<'_, Self>>()?.enqueue(chunk);
                }
            }
        }
        Ok(())
    }

    #[inline]
    fn read(
        &mut self,
        py: Python<'_>,
        n: isize,
        retired: &mut RetiredChunks,
    ) -> PyResult<Py<PyBytes>> {
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
            retired.push(self.chunks.pop_front().unwrap().data, py);
        }
        if self.chunks.is_empty() {
            return Ok(PyBytes::new(py, b"").unbind());
        }

        let requested = n as usize;
        let output_len = requested.min(self.size);
        if let Some(chunk) = self.chunks.front() {
            let chunk_len = chunk.len - chunk.offset;
            if chunk.offset == 0
                && chunk_len == requested
                && matches!(&chunk.data, BytesChunkData::Bytes(_))
            {
                self.size -= requested;
                let chunk = self.chunks.pop_front().unwrap();
                if let BytesChunkData::Bytes(data) = chunk.data {
                    return Ok(data);
                }
                unreachable!();
            }
        }

        let output = self.copy_output(py, output_len, retired)?;

        // Do not consume any input until all fallible output work succeeds.
        self.size -= output_len;
        let mut remaining = output_len;
        while let Some(chunk) = self.chunks.front_mut() {
            let available = chunk.len - chunk.offset;
            if remaining < available {
                chunk.offset += remaining;
                break;
            }
            remaining -= available;
            retired.push(self.chunks.pop_front().unwrap().data, py);
        }
        Ok(output.unbind())
    }
    fn prepare_chunk(data: &Bound<'_, PyAny>, skip_empty: bool) -> PyResult<Option<BytesChunk>> {
        let (data, len) = if let Ok(data) = data.cast::<PyBytes>() {
            (
                BytesChunkData::Bytes(data.clone().unbind()),
                data.as_bytes().len(),
            )
        } else {
            // Keep put_many's existing treatment of empty iterable items.
            if skip_empty && !data.is_instance_of::<PyMemoryView>() && data.len()? == 0 {
                return Ok(None);
            }
            data.cast::<PyMemoryView>()?;
            #[cfg(all(not(queue_native_buffer), not(Py_GIL_DISABLED)))]
            {
                // A C-contiguous view covering an exact bytes owner can retain
                // that immutable payload directly. Equal byte counts exclude
                // offset slices; contiguity excludes reversed/strided views.
                // Do not use readonly here: a readonly view may wrap mutable
                // storage. Exclude subclasses and their buffer/finalizer hooks.
                let py = data.py();
                let owner = data.getattr(intern!(py, "obj"))?;
                if owner.is_exact_instance_of::<PyBytes>() {
                    let owner = unsafe { owner.cast_into_unchecked::<PyBytes>() };
                    let len = data.getattr(intern!(py, "nbytes"))?.extract::<usize>()?;
                    if owner.as_bytes().len() == len
                        && data.getattr(intern!(py, "c_contiguous"))?.is_truthy()?
                    {
                        return Ok(if skip_empty && len == 0 {
                            None
                        } else {
                            Some(BytesChunk {
                                data: BytesChunkData::Bytes(owner.unbind()),
                                offset: 0,
                                len,
                            })
                        });
                    }
                }
            }
            let (view, len, contiguous) = Self::own_view(data)?;
            (
                BytesChunkData::MemoryView {
                    data: view.unbind(),
                    contiguous,
                },
                len,
            )
        };
        if skip_empty && len == 0 {
            return Ok(None);
        }
        Ok(Some(BytesChunk {
            data,
            offset: 0,
            len,
        }))
    }

    fn enqueue(&mut self, chunk: BytesChunk) {
        #[cfg(queue_native_buffer)]
        if chunk.len != 0
            && matches!(
                chunk.data,
                BytesChunkData::MemoryView {
                    contiguous: false,
                    ..
                }
            )
        {
            self.strided_chunks += 1;
        }
        self.size += chunk.len;
        self.chunks.push_back(chunk);
    }

    #[cfg(queue_native_buffer)]
    fn own_view<'py>(data: &Bound<'py, PyAny>) -> PyResult<(Bound<'py, PyAny>, usize, bool)> {
        queue_buffer::with_buffer(data, |buffer| {
            let len = buffer.len as usize;
            let contiguous = unsafe { pyo3::ffi::PyBuffer_IsContiguous(buffer, b'C' as _) != 0 };
            // Retain an independent view, without a Python-level cast or
            // attribute lookup. The export stays valid until this view dies.
            Ok((PyMemoryView::from(data)?.into_any(), len, contiguous))
        })
    }

    #[cfg(all(not(queue_native_buffer), not(Py_GIL_DISABLED)))]
    fn own_view<'py>(data: &Bound<'py, PyAny>) -> PyResult<(Bound<'py, PyAny>, usize, bool)> {
        let py = data.py();
        // A successful cast both checks C contiguity and gives a one-dimensional
        // byte view, whose length is the byte count. Avoid separate attribute
        // lookups and Python integer allocation for ordinary contiguous input.
        match data.call_method1(intern!(py, "cast"), (intern!(py, "B"),)) {
            Ok(view) => {
                let len = view.len()?;
                Ok((view, len, true))
            }
            Err(err) if err.is_instance_of::<pyo3::exceptions::PyTypeError>(py) => {
                // Strided views and empty shapes cannot always be cast. Keep an
                // independent view and defer flattening until a read needs it.
                let view = PyMemoryView::from(data)?.into_any();
                let len = view.getattr(intern!(py, "nbytes"))?.extract::<usize>()?;
                Ok((view, len, false))
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(Py_GIL_DISABLED)]
    fn own_view<'py>(data: &Bound<'py, PyAny>) -> PyResult<(Bound<'py, PyAny>, usize, bool)> {
        let py = data.py();
        let (len, contiguous) = queue_buffer::with_buffer(data, |buffer| {
            // Metadata is stable for the lifetime of the export. On free-threaded
            // Python we never read payload memory through this descriptor.
            Ok((buffer.len as usize, unsafe {
                pyo3::ffi::PyBuffer_IsContiguous(buffer, b'C' as _) != 0
            }))
        })?;
        // Empty shapes cannot always be cast. Own an independent view so
        // releasing the caller's view cannot invalidate queued data.
        let view = if contiguous && len != 0 {
            data.call_method1(intern!(py, "cast"), (intern!(py, "B"),))?
        } else {
            PyMemoryView::from(data)?.into_any()
        };
        Ok((view, len, contiguous))
    }

    #[cfg(not(queue_native_buffer))]
    fn buffer_bytes<'py>(data: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
        // This stable-ABI entry point lets CPython acquire and copy the buffer,
        // avoiding a Python method lookup. It returns exact bytes or an error.
        unsafe {
            Ok(Bound::from_owned_ptr_or_err(
                data.py(),
                pyo3::ffi::PyBytes_FromObject(data.as_ptr()),
            )?
            .cast_into_unchecked())
        }
    }

    #[cfg(not(queue_native_buffer))]
    fn copy_small_views(py: Python<'_>) -> bool {
        // Python 3.7/3.8 show severe allocator churn with join(memoryviews).
        // Bounded copies avoid it there; newer runtimes perform better with join.
        // Py_GetVersion is process-wide and does not invoke Python callbacks.
        static USE_COPIES: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *USE_COPIES.get_or_init(|| py.version_info() < (3, 9))
    }

    #[cfg(not(queue_native_buffer))]
    fn copy_output<'py>(
        &mut self,
        py: Python<'py>,
        output_len: usize,
        retired: &mut RetiredChunks,
    ) -> PyResult<Bound<'py, PyBytes>> {
        // A complete view already knows how to produce the final bytes object.
        // This also avoids flattening a complete strided view into a separate
        // temporary payload. Consumption and owner release still happen later.
        if let Some(chunk) = self.chunks.front() {
            if chunk.offset == 0 && chunk.len == output_len {
                if let BytesChunkData::MemoryView { data, .. } = &chunk.data {
                    return Self::buffer_bytes(data.bind(py));
                }
            }
        }
        let mut remaining = output_len;
        let mut has_views = false;
        let mut small_views = true;
        let mut chunk_count = 0;
        for chunk in &mut self.chunks {
            if remaining == 0 {
                break;
            }
            if let BytesChunkData::MemoryView {
                data,
                contiguous: false,
            } = &chunk.data
            {
                // Strided views still need flattening; cache it for partial reads.
                let data = Self::buffer_bytes(data.bind(py))?;
                retired.push(
                    std::mem::replace(&mut chunk.data, BytesChunkData::Bytes(data.unbind())),
                    py,
                );
            }
            has_views |= matches!(&chunk.data, BytesChunkData::MemoryView { .. });
            if matches!(&chunk.data, BytesChunkData::MemoryView { .. }) {
                small_views &= chunk.len <= 32 * 1024;
            }
            remaining -= remaining.min(chunk.len - chunk.offset);
            chunk_count += 1;
        }
        if remaining != 0 {
            return Err(pyo3::exceptions::PyRuntimeError::new_err(
                "byte queue size invariant violated",
            ));
        }

        let output = if has_views && chunk_count == 1 {
            let chunk = self.chunks.front().unwrap();
            let BytesChunkData::MemoryView { data, .. } = &chunk.data else {
                unreachable!();
            };
            let view = if chunk.offset == 0 && output_len == chunk.len {
                data.bind(py).clone()
            } else {
                data.bind(py).get_item(PySlice::new(
                    py,
                    chunk.offset as isize,
                    (chunk.offset + output_len) as isize,
                    1,
                ))?
            };
            Self::buffer_bytes(&view)?
        } else if has_views && !(small_views && Self::copy_small_views(py)) {
            // join copies contiguous buffers directly into the result using
            // Python's buffer API, which abi3-py37 cannot access from Rust.
            let parts = PyList::empty(py);
            let mut remaining = output_len;
            for chunk in self.chunks.iter().take(chunk_count) {
                let copied = remaining.min(chunk.len - chunk.offset);
                if copied == 0 {
                    continue;
                }
                let data = match &chunk.data {
                    BytesChunkData::Bytes(data) => data.bind(py).as_any(),
                    BytesChunkData::MemoryView { data, .. } => data.bind(py),
                };
                if let Ok(bytes) = data.cast::<PyBytes>() {
                    if !bytes.is_exact_instance_of::<PyBytes>() {
                        // A subclass's __buffer__ may disagree with its bytes payload.
                        parts.append(PyBytes::new(
                            py,
                            &bytes.as_bytes()[chunk.offset..chunk.offset + copied],
                        ))?;
                        remaining -= copied;
                        continue;
                    }
                }
                if chunk.offset == 0 && copied == chunk.len {
                    parts.append(data)?;
                } else {
                    let view = if data.is_instance_of::<PyBytes>() {
                        PyMemoryView::from(data)?.into_any()
                    } else {
                        data.clone()
                    };
                    parts.append(view.get_item(PySlice::new(
                        py,
                        chunk.offset as isize,
                        (chunk.offset + copied) as isize,
                        1,
                    ))?)?;
                }
                remaining -= copied;
            }
            PyBytes::new(py, b"")
                .call_method1(intern!(py, "join"), (parts,))?
                .cast_into::<PyBytes>()?
        } else {
            // Bytes-only reads need no per-chunk allocation. On Python 3.7/3.8,
            // small views use temporaries bounded to 32 KiB instead of join.
            // Copy only the consumed prefix; never snapshot an unread mutable tail.
            // The unpublished result is uninitialized: write via raw pointers,
            // never a Rust u8 slice, and initialize every byte before returning.
            unsafe {
                let ptr =
                    pyo3::ffi::PyBytes_FromStringAndSize(std::ptr::null(), output_len as isize);
                let bytes: Bound<'_, PyBytes> =
                    Bound::from_owned_ptr_or_err(py, ptr)?.cast_into_unchecked();
                let buffer = pyo3::ffi::PyBytes_AsString(ptr).cast::<u8>();
                let mut written = 0;
                for chunk in self.chunks.iter().take(chunk_count) {
                    let copied = (chunk.len - chunk.offset).min(output_len - written);
                    if copied == 0 {
                        continue;
                    }
                    let temporary;
                    let source = match &chunk.data {
                        BytesChunkData::Bytes(data) => {
                            &data.bind(py).as_bytes()[chunk.offset..chunk.offset + copied]
                        }
                        BytesChunkData::MemoryView { data, .. } => {
                            let view = if chunk.offset == 0 && copied == chunk.len {
                                data.bind(py).clone()
                            } else {
                                data.bind(py).get_item(PySlice::new(
                                    py,
                                    chunk.offset as isize,
                                    (chunk.offset + copied) as isize,
                                    1,
                                ))?
                            };
                            temporary = Self::buffer_bytes(&view)?;
                            temporary.as_bytes()
                        }
                    };
                    std::ptr::copy_nonoverlapping(source.as_ptr(), buffer.add(written), copied);
                    written += copied;
                }
                bytes
            }
        };

        Ok(output)
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
