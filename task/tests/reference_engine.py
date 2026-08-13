"""Independent reference capture for RingVault (verify-time only).

Drives the vaultlab binary over the same TLV frame protocol as the oracle
solution, capturing real vault flags from sealed test-input case directories.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import subprocess
from pathlib import Path

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


def _vault_salt() -> bytes:
    return bytes((h << 4) | l for h, l in zip(SALT_HI, SALT_LO))


def _compute_gate_tag(challenge_id: str, script_pos: int, event_code: int) -> str:
    material = (
        _vault_salt()
        + challenge_id.encode()
        + b"|"
        + str(script_pos).encode()
        + b"|"
        + str(event_code).encode()
    )
    return hashlib.sha256(material).digest()[:8].hex()


def _decode_schedule(challenge_id: str, sched_hex: str) -> list[int]:
    salt = _vault_salt()
    key = hashlib.sha256(salt + challenge_id.encode()).digest()
    cipher = bytes.fromhex(sched_hex)
    plain = bytes(c ^ key[j % 32] for j, c in enumerate(cipher))
    n = plain[0]
    if n <= 0 or len(cipher) != n + 1:
        raise RuntimeError(f"bad sched_hex for {challenge_id}")
    events: list[int] = []
    for i in range(n):
        idx = plain[1 + i] ^ key[i % 32]
        logical = OPC_SBOX.get(idx)
        if logical is None:
            raise RuntimeError(f"unknown opcode in {challenge_id} at {i}")
        events.append(logical)
    return events


def _encode_tlv(typ: int, value: bytes) -> bytes:
    return struct.pack("!BH", typ, len(value)) + value


def _encode_frame(body: bytes) -> bytes:
    return struct.pack("!I", len(body)) + body


def _decode_frame(data: bytes) -> bytes:
    length = struct.unpack("!I", data[:4])[0]
    return data[4 : 4 + length]


def _decode_tlvs(body: bytes):
    offset = 0
    while offset < len(body):
        typ = body[offset]
        vlen = struct.unpack("!H", body[offset + 1 : offset + 3])[0]
        offset += 3
        yield typ, body[offset : offset + vlen]
        offset += vlen


def _wrap_nested(inner: bytes, depth: int) -> bytes:
    cur = inner
    for _ in range(depth):
        cur = _encode_tlv(TYPE_NEST, cur)
    return cur


def _compute_tag(key: bytes, material: bytes) -> bytes:
    return hashlib.sha256(key + b"|" + material).digest()


class _BinaryLab:
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


def _solve_case(case_dir: str) -> str:
    with open(os.path.join(case_dir, "case.json"), encoding="utf-8") as f:
        case = json.load(f)

    cid = case["challenge_id"]
    schedule = _decode_schedule(cid, case["sched_hex"])
    lab = _BinaryLab(case_dir)
    key = bytes.fromhex(case["key_hex"])
    slot = case["slot"]
    scope = case["scope"]
    nest_required = case["nest_required"]
    live_ticket: bytes | None = None

    try:
        for script_pos, event in enumerate(schedule):
            if event == EVT_TICK:
                continue
            if event == EVT_REINCARNATE:
                live_ticket = None
                continue

            if event == EVT_HOLD:
                gtag = _compute_gate_tag(cid, script_pos, EVT_HOLD)
                if live_ticket is not None:
                    hold_mat = f"hold|{live_ticket.hex()}|{gtag}".encode()
                else:
                    hold_mat = f"hold|-|{gtag}".encode()
                hold_tag = _compute_tag(key, hold_mat)
                reply = lab.step(_encode_frame(_encode_tlv(TYPE_HOLD_SEAL, hold_tag)))
                held = any(
                    typ == TYPE_NOTE and val == b"held"
                    for typ, val in _decode_tlvs(_decode_frame(reply))
                )
                if not held:
                    raise RuntimeError(f"hold failed for {cid} pos {script_pos}")

            elif event == EVT_TICKET:
                gtag = _compute_gate_tag(cid, script_pos, EVT_TICKET)
                req = f"{slot}|{scope}|request|{gtag}".encode()
                tag = _compute_tag(key, req)
                if nest_required == 0:
                    tag = tag[:4]
                body = _encode_tlv(TYPE_AUTH, tag) + _encode_tlv(TYPE_NOTE, b"session")
                reply = lab.step(_encode_frame(body))
                got_ticket = None
                for typ, val in _decode_tlvs(_decode_frame(reply)):
                    if typ == TYPE_TICKET:
                        got_ticket = val
                if got_ticket is None:
                    raise RuntimeError(f"no ticket for {cid} pos {script_pos}")
                live_ticket = got_ticket

                cont_mat = f"cont|{live_ticket.hex()}|{gtag}".encode()
                cont_tag = _compute_tag(key, cont_mat)
                lab.step(_encode_frame(_encode_tlv(TYPE_CONTINUE, cont_tag)))

            elif event == EVT_CLAIM:
                if live_ticket is None:
                    raise RuntimeError(f"no ticket at claim for {cid}")
                gtag = _compute_gate_tag(cid, script_pos, EVT_CLAIM)
                mat = f"{slot}|{scope}|{live_ticket.hex()}|{gtag}".encode()
                tag = _compute_tag(key, mat)
                if nest_required == 0:
                    tag = tag[:4]
                inner = (
                    _encode_tlv(TYPE_AUTH, tag)
                    + _encode_tlv(TYPE_CLAIM, scope.encode())
                    + _encode_tlv(TYPE_TICKET, live_ticket)
                )
                body = _wrap_nested(inner, nest_required)
                reply = lab.step(_encode_frame(body))
                for typ, val in _decode_tlvs(_decode_frame(reply)):
                    if typ == TYPE_REPLY:
                        return val.decode("utf-8")
                raise RuntimeError(f"no REPLY for {cid}")
    finally:
        lab.close()

    raise RuntimeError(f"schedule ended without claim for {cid}")


def capture_all_work_flags() -> dict[str, str]:
    """Capture flags by driving vaultlab against sealed test inputs."""
    root = Path("/tests/inputs")
    out: dict[str, str] = {}
    for case_path in sorted(root.iterdir()):
        if not case_path.is_dir():
            continue
        if not (case_path / "case.json").is_file():
            continue
        flag = _solve_case(str(case_path))
        out[case_path.name] = flag
    return out
