from __future__ import annotations

from jh2.frame_buffer import FrameBuffer
from jh2.hyperframe.frame import FRAMES, DataFrame, ExtensionFrame


def test_custom_frame_retains_body_after_buffer_compaction(monkeypatch):
    class CustomFrame(ExtensionFrame):
        def __init__(self, stream_id):
            super().__init__(type=0xFE, stream_id=stream_id)

        def parse_body(self, data):
            self.body = data
            self.body_len = len(data)

    monkeypatch.setitem(FRAMES, 0xFE, CustomFrame)
    buffer = FrameBuffer()
    buffer.max_frame_size = 2**14
    buffer.add_data(b"\x00\x00\x03\xfe\x00\x00\x00\x00\x01abc")

    frame = next(buffer)

    assert isinstance(frame, CustomFrame)
    assert isinstance(frame.body, memoryview)
    assert frame.body.tobytes() == b"abc"
    buffer.add_data(b"more data")
    assert frame.body.tobytes() == b"abc"


def test_consumed_data_is_compacted_when_partial_frame_remains():
    complete = DataFrame(1, data=b"complete").serialize()
    partial = DataFrame(1, data=b"partial").serialize()
    buffer = FrameBuffer()
    buffer.max_frame_size = 2**14
    buffer.add_data(complete + partial[:5])

    assert [frame.data for frame in buffer] == [b"complete"]
    assert buffer._data_offset == 0
    assert buffer._data == partial[:5]

    buffer.add_data(partial[5:])
    assert [frame.data for frame in buffer] == [b"partial"]


def test_padded_data_frame_serializes_memoryview():
    frame = DataFrame(1, data=memoryview(b"data"), pad_length=2)
    frame.flags.add("PADDED")

    assert frame.serialize() == b"\x00\x00\x07\x00\x08\x00\x00\x00\x01\x02data\x00\x00"
