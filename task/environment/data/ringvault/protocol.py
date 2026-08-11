"""
RingVault framed TLV protocol.

Outer frame: 4-byte big-endian length prefix + body.
Body: sequence of TLV records.
  - 1-byte type
  - 2-byte big-endian length
  - value (length bytes)

Types:
  0x01  AUTH    -- seal tag credential
  0x02  NOTE    -- informational payload
  0x03  NEST    -- value is an inner TLV sequence (recursive container)
  0x04  CLAIM   -- vault claim request (value = scope string)
  0x05  REPLY   -- server reply (value = flag string or status)
"""

import struct

TYPE_AUTH = 0x01
TYPE_NOTE = 0x02
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05


def encode_tlv(typ: int, value: bytes) -> bytes:
    """Encode a single TLV record."""
    return struct.pack("!BH", typ, len(value)) + value


def encode_frame(body: bytes) -> bytes:
    """Wrap a TLV body in a 4-byte length-prefixed frame."""
    return struct.pack("!I", len(body)) + body


def decode_frame(data: bytes) -> bytes:
    """Strip the 4-byte length prefix and return the body."""
    if len(data) < 4:
        raise ValueError("frame too short")
    (length,) = struct.unpack("!I", data[:4])
    body = data[4:]
    if len(body) < length:
        raise ValueError("truncated frame")
    return body[:length]


def decode_tlvs(body: bytes):
    """Return list of (type, value) pairs from a TLV body."""
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
    """
    Wrap a list of (type, value) in *depth* layers of NEST containers.
    depth=0 returns flat concatenation.
    """
    inner = b"".join(encode_tlv(t, v) for t, v in records)
    for _ in range(depth):
        inner = encode_tlv(TYPE_NEST, inner)
    return inner
