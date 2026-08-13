#!/usr/bin/env python3
"""Oracle solution for RingVault CTF (binary protocol driver)."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess

TYPE_AUTH = 0x01
TYPE_NOTE = 0x02
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05
TYPE_TICKET = 0x06
TYPE_CONTINUE = 0x07
TYPE_HOLD_SEAL = 0x08

EVT_TICK = 1
EVT_REINCARNATE = 2
EVT_TICKET = 3
EVT_CLAIM = 4
EVT_HOLD = 5

VAULTLAB = "/app/data/bin/vaultlab"

SALT_HI = bytes([
    0x6, 0x2, 0x9, 0xc, 0x5, 0xa, 0x3, 0xf,
    0x1, 0x9, 0x4, 0xe, 0x8, 0x5, 0xd, 0x0,
])
SALT_LO = bytes([
    0xb, 0xe, 0x1, 0x4, 0x7, 0x8, 0xd, 0x0,
    0xc, 0xb, 0x4, 0x7, 0x2, 0xa, 0x6, 0xf,
])
OPC_SBOX = {
    0x17: EVT_TICK,
    0x2a: EVT_REINCARNATE,
    0x3d: EVT_TICKET,
    0x4e: EVT_CLAIM,
    0x5b: EVT_HOLD,
}


def vault_salt() -> bytes:
    return bytes((h << 4) | l for h, l in zip(SALT_HI, SALT_LO))


def compute_gate_tag(challenge_id: str, script_pos: int, event_code: int) -> bytes:
    material = (
        vault_salt()
        + challenge_id.encode()
        + b"|"
        + str(script_pos).encode()
        + b"|"
        + str(event_code).encode()
    )
    return hashlib.sha256(material).digest()[:8]


def decode_schedule(challenge_id: str, sched_hex: str) -> list[int]:
    salt = vault_salt()
    key = hashlib.sha256(salt + challenge_id.encode()).digest()
    cipher = bytes.fromhex(sched_hex)
    plain = bytes(c ^ key[j % 32] for j, c in enumerate(cipher))
    n = plain[0]
    if n <= 0 or len(cipher) != n + 1:
        raise RuntimeError(f"bad sched_hex length for {challenge_id}")
    events = []
    for i in range(n):
        idx = plain[1 + i] ^ key[i % 32]
        logical = OPC_SBOX.get(idx)
        if logical is None:
            raise RuntimeError(f"unknown opcode in {challenge_id} at {i}")
        events.append(logical)
    return events


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

    cid = case["challenge_id"]
    schedule = decode_schedule(cid, case["sched_hex"])

    lab = BinaryLab(case_dir)
    key = bytes.fromhex(case["key_hex"])
    slot = case["slot"]
    scope = case["scope"]
    nest_required = case["nest_required"]

    live_ticket = None

    try:
        for script_pos, event in enumerate(schedule):
            if event == EVT_TICK:
                continue
            if event == EVT_REINCARNATE:
                live_ticket = None
                continue
            if event == EVT_HOLD:
                gtag = compute_gate_tag(cid, script_pos, EVT_HOLD)
                if live_ticket is not None:
                    hold_mat = f"hold|{live_ticket.hex()}|".encode() + gtag
                else:
                    hold_mat = b"hold|-|" + gtag
                hold_tag = compute_tag(key, hold_mat)
                reply_data = lab.step(encode_frame(encode_tlv(TYPE_HOLD_SEAL, hold_tag)))
                held = False
                for typ, val in decode_tlvs(decode_frame(reply_data)):
                    if typ == TYPE_NOTE and val == b"held":
                        held = True
                if not held:
                    raise RuntimeError(f"hold gate failed for {cid} at {script_pos}")
            elif event == EVT_TICKET:
                gtag = compute_gate_tag(cid, script_pos, EVT_TICKET)
                req = f"{slot}|{scope}|request|".encode() + gtag
                tag = compute_tag(key, req)
                if nest_required == 0:
                    tag = tag[:4]
                body = encode_tlv(TYPE_AUTH, tag) + encode_tlv(TYPE_NOTE, b"session")
                reply_data = lab.step(encode_frame(body))
                got_ticket = None
                for typ, val in decode_tlvs(decode_frame(reply_data)):
                    if typ == TYPE_TICKET:
                        got_ticket = val
                if got_ticket is None:
                    raise RuntimeError(f"no ticket for {cid} at {script_pos}")
                live_ticket = got_ticket

                cont_material = f"cont|{live_ticket.hex()}|".encode() + gtag
                cont_tag = compute_tag(key, cont_material)
                lab.step(encode_frame(encode_tlv(TYPE_CONTINUE, cont_tag)))
            elif event == EVT_CLAIM:
                if live_ticket is None:
                    raise RuntimeError(f"no live ticket at claim for {cid}")
                gtag = compute_gate_tag(cid, script_pos, EVT_CLAIM)
                material = f"{slot}|{scope}|{live_ticket.hex()}|".encode() + gtag
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
                raise RuntimeError(f"No REPLY for {cid}")
    finally:
        lab.close()

    raise RuntimeError(f"schedule ended without claim for {cid}")


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