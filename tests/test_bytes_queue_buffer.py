from __future__ import annotations

import ctypes
import gc
import platform
import sys
import weakref
from array import array
from collections import deque
from concurrent.futures import ThreadPoolExecutor

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

try:
    import tracemalloc
except ImportError:
    # Some PyPy builds ship the wrapper without the native _tracemalloc module.
    tracemalloc = None

try:
    from jh2._hazmat import _BytesQueueBuffer
except ImportError:
    _BytesQueueBuffer = None


pytestmark = pytest.mark.skipif(
    _BytesQueueBuffer is None,
    reason="native byte queue is unavailable",
)
cpython_only = pytest.mark.skipif(
    platform.python_implementation() != "CPython",
    reason="asserts CPython reference-release timing",
)
requires_tracemalloc = pytest.mark.skipif(
    tracemalloc is None,
    reason="tracemalloc is unavailable",
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
view_stride_strategy = st.sampled_from((0, 1, 2, -1))
operation_strategy = st.one_of(
    st.tuples(st.just("put"), chunk_strategy, view_stride_strategy),
    st.tuples(
        st.just("put_many"),
        st.lists(chunk_strategy, max_size=8),
        view_stride_strategy,
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


@pytest.mark.parametrize("reported_length", (0, 100))
@pytest.mark.parametrize("batch", (False, True))
def test_bytes_subclass_length_does_not_change_byte_accounting(reported_length, batch):
    class MisleadingBytes(bytes):
        def __len__(self):
            return reported_length

    buffer = _BytesQueueBuffer()
    if batch:
        buffer.put_many([MisleadingBytes(b"abc")])
    else:
        buffer.put(MisleadingBytes(b"abc"))
    assert len(buffer) == 3
    assert buffer.get(2) == b"ab"
    assert buffer.get(2) == b"c"


@pytest.mark.parametrize("chunks", ((b"abc", b"x"), (b"x", b"abc")))
@pytest.mark.parametrize("read_size", (2, 4))
def test_mixed_read_uses_bytes_payload_not_subclass_buffer(chunks, read_size):
    class MisleadingBytes(bytes):
        def __buffer__(self, flags):
            return memoryview(b"OVERRIDE")

    buffer = _BytesQueueBuffer()
    buffer.put_many(
        [
            MisleadingBytes(chunk) if chunk == b"abc" else memoryview(chunk)
            for chunk in chunks
        ]
    )
    expected = b"".join(chunks)
    assert buffer.get(read_size) == expected[:read_size]
    if read_size < len(expected):
        assert buffer.get(100) == expected[read_size:]
    assert len(buffer) == 0


def test_multiple_chunks_and_oversized_read():
    buffer = _BytesQueueBuffer()
    buffer.put_many([b"foo", b"", b"bar", b"baz"])

    assert len(buffer) == 9
    assert buffer.get(4) == b"foob"
    assert buffer.get(100) == b"arbaz"


def test_put_many_iterator_can_reenter_queue():
    buffer = _BytesQueueBuffer()

    def chunks():
        buffer.put(b"before")
        yield b"prefix"
        assert buffer.get(12) == b"beforeprefix"
        buffer.put(b"nested")
        yield b"suffix"

    buffer.put_many(chunks())
    assert buffer.get(100) == b"nestedsuffix"


def test_put_many_iterator_can_hand_queue_to_another_thread():
    buffer = _BytesQueueBuffer()

    def consume_prefix():
        assert len(buffer) == 6
        assert buffer.get(6) == b"prefix"
        buffer.put(b"nested")

    with ThreadPoolExecutor(max_workers=1) as executor:
        def chunks():
            yield b"prefix"
            executor.submit(consume_prefix).result(timeout=10)
            yield b"suffix"

        buffer.put_many(chunks())

    assert buffer.get(100) == b"nestedsuffix"


def test_put_many_length_callback_can_reenter_queue():
    buffer = _BytesQueueBuffer()

    class EmptyItem:
        def __len__(self):
            buffer.put(b"nested")
            return 0

    buffer.put_many([b"prefix", EmptyItem(), b"suffix"])
    assert buffer.get(100) == b"prefixnestedsuffix"


def test_put_many_observes_items_appended_to_input_by_callback():
    buffer = _BytesQueueBuffer()

    class EmptyItem:
        def __len__(self):
            chunks.append(b"appended")
            return 0

    chunks = [b"prefix", EmptyItem()]
    buffer.put_many(chunks)
    assert buffer.get(100) == b"prefixappended"


@pytest.mark.parametrize("base", (list, tuple))
def test_put_many_respects_sequence_subclass_iteration(base):
    buffer = _BytesQueueBuffer()

    class Chunks(base):
        def __iter__(self):
            buffer.put(b"nested")
            yield b"override"

    buffer.put_many(Chunks([b"unused"]))
    assert buffer.get(100) == b"nestedoverride"


def test_put_many_iterator_error_keeps_completed_appends():
    buffer = _BytesQueueBuffer()

    def chunks():
        yield b"prefix"
        assert len(buffer) == 6
        raise ValueError("iterator failed")

    with pytest.raises(ValueError, match="iterator failed"):
        buffer.put_many(chunks())
    buffer.put(b"suffix")
    assert buffer.get(100) == b"prefixsuffix"


@cpython_only
@pytest.mark.parametrize("sequence", (list, tuple))
def test_put_many_view_allocation_gc_can_reenter_queue(sequence):
    if not getattr(sys, "_is_gil_enabled", lambda: True)():
        pytest.skip("free-threaded GC does not obey allocation thresholds alone")

    buffer = _BytesQueueBuffer()
    chunks = sequence([b"x"] + [memoryview(bytearray(b"x")) for _ in range(100)])
    observations = []

    def observe_collection(phase, info):
        if phase == "start":
            try:
                observations.append(len(buffer))
            except BaseException as exc:
                observations.append(exc)

    was_enabled = gc.isenabled()
    thresholds = gc.get_threshold()
    gc.collect()
    gc.callbacks.append(observe_collection)
    try:
        gc.enable()
        gc.set_threshold(1, 0, 0)
        buffer.put_many(chunks)
    finally:
        gc.callbacks.remove(observe_collection)
        gc.set_threshold(*thresholds)
        if not was_enabled:
            gc.disable()

    assert all(isinstance(value, int) for value in observations), observations
    # Newer CPython can defer automatic collections until after the C call.
    if sys.version_info < (3, 12):
        assert any(0 < value < len(chunks) for value in observations)
    assert buffer.get(len(chunks)) == b"x" * len(chunks)


@cpython_only
@pytest.mark.parametrize("kind", ("bytes", "view", "strided"))
@pytest.mark.parametrize("count", (1, 32))
def test_consumed_chunk_finalizers_can_reenter_queue(kind, count):
    buffer = _BytesQueueBuffer()
    observations = []

    def finalize():
        try:
            observations.append(len(buffer))
            buffer.put(b"!")
        except BaseException as exc:
            observations.append(exc)

    class BytesOwner(bytes):
        def __del__(self):
            finalize()

    class ViewOwner(bytearray):
        def __del__(self):
            finalize()

    for _ in range(count):
        if kind == "bytes":
            buffer.put(BytesOwner(b"abc"))
        else:
            stride = 2 if kind == "strided" else 1
            payload = b"a_b_c_" if stride == 2 else b"abc"
            buffer.put(memoryview(ViewOwner(payload))[::stride])
    buffer.put(b"tail")

    assert buffer.get(3 * count) == b"abc" * count
    assert observations == list(range(4, 4 + count))
    assert buffer.get(100) == b"tail" + b"!" * count


@cpython_only
@pytest.mark.parametrize("kind", ("bytes", "view"))
def test_empty_chunk_finalizer_can_read_and_write_queue(kind):
    buffer = _BytesQueueBuffer()
    observations = []

    class Owner(bytes if kind == "bytes" else bytearray):
        def __del__(self):
            try:
                observations.append(buffer.get(4))
                buffer.put(b"nested")
            except BaseException as exc:
                observations.append(exc)

    buffer.put(Owner(b"") if kind == "bytes" else memoryview(Owner(b"")))
    buffer.put(b"prefixtail")

    assert buffer.get(6) == b"prefix"
    assert observations == [b"tail"]
    assert buffer.get(100) == b"nested"


@cpython_only
@pytest.mark.parametrize("fail", (False, True))
def test_strided_owner_finalizer_runs_after_partial_read_or_error(fail):
    buffer = _BytesQueueBuffer()
    observations = []

    class Owner(bytearray):
        def __del__(self):
            try:
                observations.append(len(buffer))
                buffer.put(b"!")
            except BaseException as exc:
                observations.append(exc)

    buffer.put(memoryview(Owner(b"a_b_c_"))[::2])
    if fail:
        buffer.put(memoryview(bytearray(b"tail")))
        queued_tail = next(
            view for view in gc.get_referents(buffer)
            if isinstance(view, memoryview) and view.nbytes == 4
        )
        queued_tail.release()
        # join() reports TypeError for a released view on the legacy/FT path.
        with pytest.raises(
            (ValueError, TypeError),
            match="released memoryview|expected a bytes-like object",
        ):
            buffer.get(7)
        assert observations == [7]
        assert buffer.get(3) == b"abc"
        assert len(buffer) == 5
    else:
        assert buffer.get(1) == b"a"
        assert observations == [2]
        assert buffer.get(100) == b"bc!"


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


@pytest.mark.parametrize(
    "source",
    [
        memoryview(b"abcdef"),
        memoryview(bytearray(b"abcdef")),
        memoryview(b"xxabcdefyy")[2:-2],
        memoryview(b"abcdef")[::2],
        memoryview(b"abcdef")[::-1],
        memoryview(b"abcdef").cast("b"),
        memoryview(b"abcdef").cast("H"),
        memoryview(b"abcdef").cast("B", shape=(2, 3)),
        memoryview(array("I", [1, 2, 3])),
        memoryview(array("I", [1, 2, 3]))[::2],
        memoryview(b"x").cast("B", shape=()),
    ],
)
def test_memoryview_byte_offsets_and_mixed_chunks(source):
    expected = b"start" + source.tobytes() + b"end"
    buffer = _BytesQueueBuffer()
    buffer.put_many([b"start", source, b"end"])
    assert len(buffer) == len(expected)
    output = []
    while len(buffer):
        chunk = buffer.get(3)
        assert type(chunk) is bytes
        output.append(chunk)
    assert b"".join(output) == expected


def test_contiguous_memoryview_remains_live_between_partial_reads():
    source = bytearray(b"abcdef")
    buffer = _BytesQueueBuffer()
    buffer.put(memoryview(source))
    assert buffer.get(3) == b"abc"
    source[3:] = b"xyz"
    assert buffer.get(3) == b"xyz"
    assert len(buffer) == 0


@pytest.mark.parametrize("batch", (False, True))
@pytest.mark.skipif(not hasattr(memoryview, "toreadonly"), reason="requires Python 3.8+")
def test_readonly_memoryview_over_mutable_storage_remains_live(batch):
    source = bytearray(b"abcdef")
    view = memoryview(source).toreadonly()
    buffer = _BytesQueueBuffer()
    if batch:
        buffer.put_many([view])
    else:
        buffer.put(view)
    view.release()
    source[0] = ord("z")
    assert buffer.get(3) == b"zbc"
    source[3:] = b"xyz"
    assert buffer.get(3) == b"xyz"


@pytest.mark.parametrize("transform", (
    lambda view: view,
    lambda view: view.cast("H"),
    lambda view: view.cast("B", shape=(2, 3)),
    lambda view: view[1:-1],
    lambda view: view[::-1],
))
def test_immutable_memoryview_survives_original_release(transform):
    view = transform(memoryview(b"abcdef"))
    expected = view.tobytes()
    buffer = _BytesQueueBuffer()
    buffer.put(view)
    view.release()
    assert buffer.get(1) == expected[:1]
    assert buffer.get(100) == expected[1:]
    assert len(buffer) == 0


@pytest.mark.parametrize("batch", (False, True))
def test_released_view_is_rejected_without_changing_queue(batch):
    buffer = _BytesQueueBuffer()
    buffer.put(b"prefix")
    view = memoryview(b"tail")
    view.release()
    with pytest.raises(ValueError, match="released memoryview"):
        if batch:
            buffer.put_many([view])
        else:
            buffer.put(view)
    assert len(buffer) == 6
    assert buffer.get(6) == b"prefix"


@pytest.mark.parametrize("stride", (1, 2))
def test_output_is_independent_of_mutable_source(stride):
    source = bytearray(b"abcdef")
    buffer = _BytesQueueBuffer()
    buffer.put(memoryview(source)[::stride])
    first = buffer.get(2)
    source[:4] = b"zzzz"
    assert first == (b"ab" if stride == 1 else b"ac")


@cpython_only
@requires_tracemalloc
def test_strided_read_does_not_allocate_output_before_flattening():
    source = bytearray(8 * 1024 * 1024)
    view = memoryview(source)[::2]
    buffer = _BytesQueueBuffer()
    buffer.put(view)
    if tracemalloc.is_tracing():
        pytest.skip("requires isolated tracemalloc measurements")
    tracemalloc.start()
    try:
        chunk = buffer.get(view.nbytes)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert chunk == view.tobytes()
    assert peak < 2 * view.nbytes + 128 * 1024


@pytest.mark.parametrize("size", (8192, 16384, 32768, 32769, 65536))
def test_mixed_view_read_preserves_live_unread_tail(size):
    first = bytearray(b"a" * size)
    second = bytearray(b"b" * size)
    buffer = _BytesQueueBuffer()
    buffer.put_many([memoryview(first), memoryview(second)])

    assert buffer.get(size + 1) == first + b"b"
    second[1:] = b"z" * (size - 1)
    assert buffer.get(size) == second[1:]
    assert len(buffer) == 0


@cpython_only
@pytest.mark.parametrize("size", (8192, 32768, 32769))
def test_failed_mixed_read_does_not_snapshot_mutable_views(size):
    source = bytearray(b"a" * size)
    buffer = _BytesQueueBuffer()
    buffer.put_many([memoryview(source), memoryview(bytearray(b"tail"))])
    queued_tail = next(
        view
        for view in gc.get_referents(buffer)
        if isinstance(view, memoryview) and view.nbytes == 4
    )
    queued_tail.release()

    with pytest.raises(ValueError, match="released memoryview"):
        buffer.get(size + 2)
    assert len(buffer) == size + 4
    source[0] = ord("z")
    assert buffer.get(size) == source
    assert len(buffer) == 4


@pytest.mark.parametrize("stride", (1, 2, -1))
def test_releasing_original_memoryview_does_not_invalidate_queue(stride):
    source = bytearray(b"abcdef")
    view = memoryview(source)[::stride]
    expected = view.tobytes()
    buffer = _BytesQueueBuffer()
    buffer.put_many([b"prefix", view, b"suffix"])
    view.release()

    assert buffer.get(7) == b"prefix" + expected[:1]
    assert buffer.get(100) == expected[1:] + b"suffix"
    assert len(buffer) == 0
    source.extend(b"ghi")


@cpython_only
def test_partial_memoryview_read_keeps_export_alive():
    source = bytearray(b"abcdef")
    buffer = _BytesQueueBuffer()
    with memoryview(source) as view:
        buffer.put(view)

    assert buffer.get(3) == b"abc"
    with pytest.raises(BufferError):
        source.extend(b"ghi")
    assert buffer.get(3) == b"def"
    source.extend(b"ghi")


@cpython_only
@pytest.mark.parametrize("stride", (1, 2))
def test_failed_read_preserves_queued_prefix_and_size(stride):
    buffer = _BytesQueueBuffer()
    buffer.put_many([b"prefix", memoryview(bytearray(b"abcdef"))[::stride]])
    size = len(buffer)
    # Invalidate the queue's own view to force a failure after a valid prefix.
    queued_view = next(v for v in gc.get_referents(buffer) if isinstance(v, memoryview))
    queued_view.release()

    with pytest.raises(ValueError, match="released memoryview"):
        buffer.get(size - 1)
    assert len(buffer) == size
    assert buffer.get(3) == b"pre"
    assert buffer.get(3) == b"fix"
    assert len(buffer) == size - 6


@pytest.mark.parametrize("shape", ((0, 3), (3, 0)))
def test_empty_multidimensional_memoryview(shape):
    source = memoryview(((ctypes.c_ubyte * shape[1]) * shape[0])())
    assert source.nbytes == 0
    buffer = _BytesQueueBuffer()

    buffer.put(source)
    assert len(buffer) == 0
    assert buffer.get(1) == b""
    buffer.put_many([source])
    with pytest.raises(RuntimeError, match="buffer is empty"):
        buffer.get(1)


@cpython_only
@requires_tracemalloc
@pytest.mark.parametrize("prefix", (b"", b"x"))
def test_partial_memoryview_read_does_not_materialize_entire_view(prefix):
    source = bytearray(4 * 1024 * 1024)
    buffer = _BytesQueueBuffer()
    buffer.put_many([prefix, memoryview(source)])
    if tracemalloc.is_tracing():
        pytest.skip("requires isolated tracemalloc measurements")
    tracemalloc.start()
    try:
        chunk = buffer.get(4096)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert chunk == prefix + bytes(4096 - len(prefix))
    assert len(buffer) == len(prefix) + len(source) - len(chunk)
    assert peak < 128 * 1024


@cpython_only
@requires_tracemalloc
@pytest.mark.parametrize("prefix", (b"", b"x", memoryview(b"x")))
@pytest.mark.parametrize("oversized", (False, True))
def test_large_memoryview_read_allocates_only_output_payload(prefix, oversized):
    source = bytearray(4 * 1024 * 1024)
    buffer = _BytesQueueBuffer()
    buffer.put_many([prefix, memoryview(source)])
    output_len = len(buffer)
    if tracemalloc.is_tracing():
        pytest.skip("requires isolated tracemalloc measurements")
    tracemalloc.start()
    try:
        chunk = buffer.get(output_len + int(oversized))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert chunk == bytes(prefix) + source
    assert len(buffer) == 0
    assert peak < output_len + 128 * 1024


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


@cpython_only
def test_dropping_queue_releases_bytes_reference():
    # Free-threaded CPython immortalizes constants, so allocate at runtime.
    chunk = bytes(bytearray(b"a sufficiently long value to avoid interning"))
    reference_count = sys.getrefcount(chunk)
    buffer = _BytesQueueBuffer()
    buffer.put(chunk)

    assert sys.getrefcount(chunk) == reference_count + 1

    del buffer
    assert sys.getrefcount(chunk) == reference_count


@cpython_only
def test_consuming_memoryview_releases_export():
    def consume_view():
        source = bytearray(b"abcdef")
        view = memoryview(source)
        view_reference = weakref.ref(view)
        buffer = _BytesQueueBuffer()
        buffer.put(view)

        assert buffer.get(6) == b"abcdef"
        return source, view_reference

    source, view_reference = consume_view()
    gc.collect()
    assert view_reference() is None

    source.extend(b"ghi")
    assert source == b"abcdefghi"


@cpython_only
def test_dropping_queue_releases_memoryview_export():
    def drop_view():
        source = bytearray(b"abcdef")
        view = memoryview(source)
        view_reference = weakref.ref(view)
        buffer = _BytesQueueBuffer()
        buffer.put(view)
        return source, view_reference

    source, view_reference = drop_view()
    gc.collect()
    assert view_reference() is None

    source.extend(b"ghi")
    assert source == b"abcdefghi"


@cpython_only
def test_memoryview_exporter_reference_cycle_is_collected():
    class BufferOwner(bytearray):
        pass

    def make_cycle():
        owner = BufferOwner(b"abcdef")
        owner_reference = weakref.ref(owner)
        buffer = _BytesQueueBuffer()
        owner.buffer = buffer
        buffer.put(memoryview(owner))
        return owner_reference

    owner_reference = make_cycle()
    gc.collect()

    assert owner_reference() is None


@settings(max_examples=500, deadline=None)
@given(st.lists(operation_strategy, min_size=1, max_size=100))
def test_operations_match_reference_buffer(operations):
    expected = ReferenceBuffer()
    actual = _BytesQueueBuffer()

    for operation in operations:
        if operation[0] == "put":
            _, data, stride = operation
            data = memoryview(data)[::stride] if stride else data
            expected.put(data)
            actual.put(data)
        elif operation[0] == "put_many":
            _, chunks, stride = operation
            if stride:
                chunks = [memoryview(chunk)[::stride] for chunk in chunks]
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
