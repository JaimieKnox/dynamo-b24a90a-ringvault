#!/usr/bin/env python3
"""Oracle solution for RingVault CTF (binary protocol driver)."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
import sys

TYPE_AUTH = 0x01
TYPE_NOTE = 0x02
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05
TYPE_TICKET = 0x06

VAULTLAB = "/app/data/bin/vaultlab"


def encode_tlv(typ, value):
    return struct.pack("!BH", typ, len(value)) + value


def encode_frame(body):
    return struct.pack("!I", len(body)) + body


def decode_frame(data):
    length = struct.unpack("!I", data[:4])[0]
    return data[4 : 4 + length]


def decode_tlvs(body):
    offset = 0
    while offset < len(body):
        typ = body[offset]
        vlen = struct.unpack("!H", body[offset + 1 : offset + 3])[0]
        offset += 3
        yield typ, body[offset : offset + vlen]
        offset += vlen


def wrap_nested(inner_body, depth):
    current = inner_body
    for _ in range(depth):
        current = encode_tlv(TYPE_NEST, current)
    return current


def compute_tag(key: bytes, material: bytes) -> bytes:
    return hashlib.sha256(key + b"|" + material).digest()


def make_material(slot: int, gen: int, scope: str, nonce: str, ticket: bytes) -> bytes:
    return f"{slot}|{gen}|{scope}|{nonce}|{ticket.hex()}".encode()


class BinaryLab:
    """Drives the vaultlab binary over stdin/stdout frames."""

    def __init__(self, case_dir: str):
        self._proc = subprocess.Popen(
            [VAULTLAB, case_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def step(self, raw_frame: bytes) -> bytes:
        self._proc.stdin.write(raw_frame)
        self._proc.stdin.flush()
        hdr = self._proc.stdout.read(4)
        if len(hdr) < 4:
            raise RuntimeError("binary closed stdout unexpectedly")
        length = struct.unpack("!I", hdr)[0]
        body = self._proc.stdout.read(length)
        return struct.pack("!I", length) + body

    def close(self):
        if self._proc.stdin:
            self._proc.stdin.close()
        self._proc.wait()


def solve_case(case_dir):
    with open(os.path.join(case_dir, "case.json"), encoding="utf-8") as f:
        case = json.load(f)

    lab = BinaryLab(case_dir)
    key = bytes.fromhex(case["key_hex"])
    slot = case["slot"]
    scope = case["scope"]
    nonces = list(case["nonces"])
    nest_required = case["nest_required"]

    gen = case["gen"]
    nonce_idx = 0
    live_ticket = None

    try:
        for event in case["script"]:
            if event == "tick":
                gen += 1
            elif event == "reincarnate":
                gen += 1
                nonce_idx = min(nonce_idx + 1, len(nonces) - 1)
                live_ticket = None
            elif event == "ticket":
                reply_data = lab.step(encode_frame(encode_tlv(TYPE_NOTE, b"session")))
                got_ticket = None
                got_gen = None
                for typ, val in decode_tlvs(decode_frame(reply_data)):
                    if typ == TYPE_TICKET:
                        got_ticket = val
                    elif typ == TYPE_NOTE:
                        got_gen = int(val.decode("ascii"))
                if got_ticket is None:
                    raise RuntimeError(f"no ticket for {case['challenge_id']}")
                live_ticket = got_ticket
                if got_gen is not None:
                    gen = got_gen
            elif event == "claim":
                if live_ticket is None:
                    raise RuntimeError(f"no live ticket at claim for {case['challenge_id']}")
                material = make_material(slot, gen, scope, nonces[nonce_idx], live_ticket)
                tag = compute_tag(key, material)
                if nest_required == 0:
                    tag = tag[:4]

                inner = (
                    encode_tlv(TYPE_AUTH, tag)
                    + encode_tlv(TYPE_CLAIM, scope.encode())
                    + encode_tlv(TYPE_TICKET, live_ticket)
                )
                body = wrap_nested(inner, nest_required)
                reply_frame = lab.step(encode_frame(body))
                for typ, val in decode_tlvs(decode_frame(reply_frame)):
                    if typ == TYPE_REPLY:
                        return val.decode("utf-8")
                raise RuntimeError(f"No REPLY for {case['challenge_id']}")
    finally:
        lab.close()

    raise RuntimeError(f"script ended without claim for {case['challenge_id']}")


def main():
    work_dir = "/app/data/work"
    results = []
    for case_name in sorted(os.listdir(work_dir)):
        case_path = os.path.join(work_dir, case_name)
        if not os.path.isdir(case_path):
            continue
        if not os.path.isfile(os.path.join(case_path, "case.json")):
            continue
        flag = solve_case(case_path)
        results.append({"id": case_name, "flag": flag})
        print(f"  {case_name}: {flag}")

    results.sort(key=lambda x: x["id"])
    output = {"challenges": results}
    os.makedirs("/app/output", exist_ok=True)
    with open("/app/output/flags.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Wrote {len(results)} flags to /app/output/flags.json")


if __name__ == "__main__":
    main()
