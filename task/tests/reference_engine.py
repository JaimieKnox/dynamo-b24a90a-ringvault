"""Independent reference capture for RingVault (verify-time only).

Pure-Python vault crypto simulation.  Does NOT subprocess anything under /app.
Reads sealed test-input case directories and recomputes flags independently.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

EVT_TICK = 1
EVT_REINCARNATE = 2
EVT_TICKET = 3
EVT_CLAIM = 4
EVT_HOLD = 5

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


def _derive_nonce(salt: bytes, challenge_id: str, nonce_idx: int) -> str:
    material = salt + challenge_id.encode() + b"|" + str(nonce_idx).encode()
    return hashlib.sha256(material).digest()[:8].hex()


def _issue_ticket(
    key: bytes, salt: bytes, challenge_id: str,
    slot: int, gen: int, nonce_idx: int,
) -> bytes:
    nonce = _derive_nonce(salt, challenge_id, nonce_idx)
    material = (
        key
        + b"|ticket|"
        + f"{slot}|{gen}|{nonce}".encode()
        + salt
    )
    return hashlib.sha256(material).digest()[:16]


def _decrypt_flag(
    key: bytes, salt: bytes,
    slot: int, gen: int, scope: str,
    ticket: bytes, vault_blob: bytes,
) -> str:
    ticket_hex = ticket.hex()
    ks_material = (
        key
        + b"|"
        + f"{slot}|{gen}|{scope}|{ticket_hex}|open".encode()
        + salt
    )
    keystream = hashlib.sha256(ks_material).digest()
    plain = bytes(vault_blob[i] ^ keystream[i % 32] for i in range(len(vault_blob)))
    return plain.decode("utf-8")


def _solve_case(case_path: str) -> str:
    with open(os.path.join(case_path, "case.json"), encoding="utf-8") as f:
        case = json.load(f)

    cid = case["challenge_id"]
    schedule = _decode_schedule(cid, case["sched_hex"])
    key = bytes.fromhex(case["key_hex"])
    salt = _vault_salt()
    slot = case["slot"]
    gen = case["gen"]
    scope = case["scope"]
    vault_blob = bytes.fromhex(case["vault_blob_hex"])
    nonce_idx = 0
    ticket: bytes | None = None

    for event in schedule:
        if event == EVT_TICK:
            gen += 1
        elif event == EVT_REINCARNATE:
            gen += 1
            nonce_idx += 1
            ticket = None
        elif event == EVT_TICKET:
            ticket = _issue_ticket(key, salt, cid, slot, gen, nonce_idx)
        elif event == EVT_CLAIM:
            if ticket is None:
                raise RuntimeError(f"no ticket at claim for {cid}")
            flag = _decrypt_flag(key, salt, slot, gen, scope, ticket, vault_blob)
            if "real_flag" in case and flag != case["real_flag"]:
                raise RuntimeError(
                    f"flag mismatch for {cid}: got {flag!r}, "
                    f"expected {case['real_flag']!r}"
                )
            return flag
        elif event == EVT_HOLD:
            pass

    raise RuntimeError(f"schedule ended without claim for {cid}")


def capture_all_work_flags() -> dict[str, str]:
    """Capture flags by simulating vault crypto against sealed test inputs."""
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
