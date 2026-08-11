#!/usr/bin/env python3
"""Example capture helper used during fit bring-up."""

from __future__ import annotations

import json
import os
import struct
import sys

TYPE_AUTH = 0x01
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05


def encode_tlv(typ: int, value: bytes) -> bytes:
    return struct.pack("!BH", typ, len(value)) + value


def encode_frame(body: bytes) -> bytes:
    return struct.pack("!I", len(body)) + body


def decode_frame(data: bytes) -> bytes:
    length = struct.unpack("!I", data[:4])[0]
    return data[4 : 4 + length]


def decode_tlvs(body: bytes):
    offset = 0
    while offset < len(body):
        typ = body[offset]
        vlen = struct.unpack("!H", body[offset + 1 : offset + 3])[0]
        offset += 3
        yield typ, body[offset : offset + vlen]
        offset += vlen


def main() -> None:
    sys.path.insert(0, "/app/data")
    from ringvault.lab import Lab

    work = "/app/data/work"
    rows = []
    for name in sorted(os.listdir(work)):
        case_dir = os.path.join(work, name)
        case = json.loads(open(os.path.join(case_dir, "case.json"), encoding="utf-8").read())
        lab = Lab(case_dir)
        # Fit-style flat short claim against the first nonce and starting generation.
        import hashlib

        key = bytes.fromhex(case["key_hex"])
        nonce = case["nonces"][0]
        material = f"{case['slot']}|{case['gen']}|{case['scope']}|{nonce}".encode()
        tag = hashlib.sha256(key + b"|" + material).digest()[:4]
        body = encode_tlv(TYPE_AUTH, tag) + encode_tlv(TYPE_CLAIM, case["scope"].encode())
        reply = lab.step(encode_frame(body))
        flag = None
        for typ, val in decode_tlvs(decode_frame(reply)):
            if typ == TYPE_REPLY:
                flag = val.decode("utf-8")
        rows.append({"id": name, "flag": flag})
    doc = {"challenges": rows}
    os.makedirs("/app/output", exist_ok=True)
    with open("/app/output/flags.json", "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")


if __name__ == "__main__":
    main()
