from __future__ import annotations

import gc
import sys
import weakref
from collections import deque

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

try:
    from jh2._hazmat import _BytesQueueBuffer
except ImportError:
    _BytesQueueBuffer = None


pytestmark = pytest.mark.skipif(
    _BytesQueueBuffer is None,
    reason="native byte queue is unavailable",
)


class ReferenceBuffer:
    def __init__(self):
        self.chunks = deque()
        self.size = 0

    def put(self, data):
        self.chunks.append(bytes(data))
        self.size += len(data)

    def put_many(self, chunks):
        for chunk in chunks:
            if chunk:
                self.put(chunk)

    def get(self, n):
        if n == 0:
            return b""
        if not self.chunks:
            raise RuntimeError("buffer is empty")
        if n < 0:
            raise ValueError("n should be > 0")

        output = bytearray()
        while len(output) < n and self.chunks:
            chunk = self.chunks.popleft()
            remaining = n - len(output)
            output += chunk[:remaining]
            if remaining < len(chunk):
                self.chunks.appendleft(chunk[remaining:])
            self.size -= min(remaining, len(chunk))
        return bytes(output)


chunk_strategy = st.binary(max_size=256)
operation_strategy = st.one_of(
    st.tuples(st.just("put"), chunk_strategy, st.booleans()),
    st.tuples(
        st.just("put_many"),
        st.lists(chunk_strategy, max_size=8),
        st.booleans(),
    ),
    st.tuples(st.just("get"), st.integers(min_value=-2, max_value=2048)),
)


def test_empty_buffer():
    buffer = _BytesQueueBuffer()

    assert len(buffer) == 0
    assert buffer.get(0) == b""
    with pytest.raises(RuntimeError, match="buffer is empty"):
        buffer.get(1)


def test_single_chunk_and_partial_reads():
    buffer = _BytesQueueBuffer()
    chunk = b"foobar"
    buffer.put(chunk)

    assert len(buffer) == 6
    assert buffer.get(2) == b"fo"
    assert len(buffer) == 4
    assert buffer.get(4) == b"obar"
    assert len(buffer) == 0


def test_exact_bytes_chunk_is_returned_without_copying():
    buffer = _BytesQueueBuffer()
    chunk = b"a sufficiently long value to avoid interning"
    buffer.put(chunk)

    assert buffer.get(len(chunk)) is chunk


def test_multiple_chunks_and_oversized_read():
    buffer = _BytesQueueBuffer()
    buffer.put_many([b"foo", b"", b"bar", b"baz"])

    assert len(buffer) == 9
    assert buffer.get(4) == b"foob"
    assert buffer.get(100) == b"arbaz"


def test_memoryview_input():
    buffer = _BytesQueueBuffer()
    buffer.put(memoryview(b"abcdef"))

    assert buffer.get(3) == b"abc"
    assert buffer.get(3) == b"def"


def test_memoryview_is_not_copied_until_consumed():
    source = bytearray(b"abcdef")
    buffer = _BytesQueueBuffer()
    buffer.put(memoryview(source))

    source[0] = ord("z")

    assert buffer.get(6) == b"zbcdef"


def test_negative_read_matches_python_buffer_ordering():
    buffer = _BytesQueueBuffer()
    with pytest.raises(RuntimeError, match="buffer is empty"):
        buffer.get(-1)

    buffer.put(b"data")
    with pytest.raises(ValueError, match="n should be > 0"):
        buffer.get(-1)


def test_empty_chunk_is_consumed():
    buffer = _BytesQueueBuffer()
    buffer.put(b"")

    assert buffer.get(1) == b""
    with pytest.raises(RuntimeError, match="buffer is empty"):
        buffer.get(1)


def test_oversized_read_consumes_trailing_empty_chunk():
    buffer = _BytesQueueBuffer()
    buffer.put(b"x")
    buffer.put(b"")

    assert buffer.get(2) == b"x"
    with pytest.raises(RuntimeError, match="buffer is empty"):
        buffer.get(1)


def test_dropping_queue_releases_bytes_reference():
    chunk = b"a sufficiently long value to avoid interning"
    reference_count = sys.getrefcount(chunk)
    buffer = _BytesQueueBuffer()
    buffer.put(chunk)

    assert sys.getrefcount(chunk) == reference_count + 1

    del buffer
    assert sys.getrefcount(chunk) == reference_count


def test_consuming_memoryview_releases_export():
    source = bytearray(b"abcdef")
    view = memoryview(source)
    view_reference = weakref.ref(view)
    buffer = _BytesQueueBuffer()
    buffer.put(view)
    del view

    assert view_reference() is not None
    assert buffer.get(6) == b"abcdef"
    gc.collect()
    assert view_reference() is None

    source.extend(b"ghi")
    assert source == b"abcdefghi"


def test_dropping_queue_releases_memoryview_export():
    source = bytearray(b"abcdef")
    view = memoryview(source)
    view_reference = weakref.ref(view)
    buffer = _BytesQueueBuffer()
    buffer.put(view)
    del view

    del buffer
    gc.collect()
    assert view_reference() is None

    source.extend(b"ghi")
    assert source == b"abcdefghi"


def test_memoryview_exporter_reference_cycle_is_collected():
    class BufferOwner(bytearray):
        pass

    owner = BufferOwner(b"abcdef")
    owner_reference = weakref.ref(owner)
    buffer = _BytesQueueBuffer()
    owner.buffer = buffer
    buffer.put(memoryview(owner))

    del buffer, owner
    gc.collect()

    assert owner_reference() is None


@settings(max_examples=500, deadline=None)
@given(st.lists(operation_strategy, min_size=1, max_size=100))
def test_operations_match_reference_buffer(operations):
    expected = ReferenceBuffer()
    actual = _BytesQueueBuffer()

    for operation in operations:
        if operation[0] == "put":
            _, data, use_memoryview = operation
            data = memoryview(data) if use_memoryview else data
            expected.put(data)
            actual.put(data)
        elif operation[0] == "put_many":
            _, chunks, use_memoryview = operation
            if use_memoryview:
                chunks = [memoryview(chunk) for chunk in chunks]
            expected.put_many(chunks)
            actual.put_many(chunks)
        else:
            _, amount = operation
            try:
                expected_result = expected.get(amount)
            except Exception as expected_error:
                with pytest.raises(type(expected_error), match=str(expected_error)):
                    actual.get(amount)
            else:
                assert actual.get(amount) == expected_result

        assert len(actual) == expected.size
