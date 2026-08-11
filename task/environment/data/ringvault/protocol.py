import struct

TYPE_AUTH = 0x01
TYPE_NOTE = 0x02
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05
TYPE_TICKET = 0x06


def encode_tlv(typ: int, value: bytes) -> bytes:
    return struct.pack("!BH", typ, len(value)) + value


def encode_frame(body: bytes) -> bytes:
    return struct.pack("!I", len(body)) + body


def decode_frame(data: bytes) -> bytes:
    if len(data) < 4:
        raise ValueError("frame too short")
    (length,) = struct.unpack("!I", data[:4])
    body = data[4:]
    if len(body) < length:
        raise ValueError("truncated frame")
    return body[:length]


def decode_tlvs(body: bytes):
    result = []
    offset = 0
    while offset < len(body):
        if offset + 3 > len(body):
            raise ValueError("truncated TLV header")
        typ = body[offset]
        (vlen,) = struct.unpack("!H", body[offset + 1 : offset + 3])
        offset += 3
        if offset + vlen > len(body):
            raise ValueError("truncated TLV value")
        result.append((typ, body[offset : offset + vlen]))
        offset += vlen
    return result


def build_nested_tlvs(records, depth: int) -> bytes:
    inner = b"".join(encode_tlv(t, v) for t, v in records)
    for _ in range(depth):
        inner = encode_tlv(TYPE_NEST, inner)
    return inner
