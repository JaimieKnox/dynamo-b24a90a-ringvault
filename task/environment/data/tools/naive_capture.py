#!/usr/bin/env python3
"""
Naive flag capture tool for RingVault.

This script correctly solves the fit/alpha challenge using a flat (depth-0)
claim with a short (4-byte) truncated seal tag. It works on any challenge
that has nest_required=0 and no reincarnation events, but it will return
decoy flags on work challenges that require nesting or generation binding.

Usage: python3 naive_capture.py CASE_DIR
"""

import hashlib
import json
import os
import struct
import sys


def encode_tlv(typ, value):
    return struct.pack("!BH", typ, len(value)) + value


def encode_frame(body):
    return struct.pack("!I", len(body)) + body


def decode_frame(data):
    length = struct.unpack("!I", data[:4])[0]
    return data[4 : 4 + length]


def decode_tlvs(body):
    offset = 0
    results = []
    while offset < len(body):
        typ = body[offset]
        vlen = struct.unpack("!H", body[offset + 1 : offset + 3])[0]
        offset += 3
        results.append((typ, body[offset : offset + vlen]))
        offset += vlen
    return results


def compute_short_tag(key_bytes, slot, gen, scope, nonce):
    material = f"{slot}|{gen}|{scope}|{nonce}".encode()
    full = hashlib.sha256(key_bytes + b"|" + material).digest()
    return full[:4]


def capture_flag(case_dir):
    with open(os.path.join(case_dir, "case.json")) as f:
        case = json.load(f)

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(case_dir))))
    from ringvault.lab import Lab

    lab = Lab(case_dir)

    key = bytes.fromhex(case["key_hex"])
    tag = compute_short_tag(
        key, case["slot"], case["gen"], case["scope"], case["nonce"]
    )

    auth_record = encode_tlv(0x01, tag)
    claim_record = encode_tlv(0x04, case["scope"].encode())
    body = auth_record + claim_record
    frame = encode_frame(body)

    reply_frame = lab.step(frame)
    reply_body = decode_frame(reply_frame)
    for typ, val in decode_tlvs(reply_body):
        if typ == 0x05:
            return val.decode("utf-8")
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 naive_capture.py CASE_DIR", file=sys.stderr)
        sys.exit(1)
    flag = capture_flag(sys.argv[1])
    print(f"Captured: {flag}")
