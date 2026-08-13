#!/usr/bin/env python3
"""Reshuffle one work schedule and recompute vault_blob_hex."""

import hashlib
import json
import os
import sys

EVT_TICK = 1
EVT_REINCARNATE = 2
EVT_TICKET = 3
EVT_CLAIM = 4
EVT_HOLD = 5

EVT_NAMES = {1: "TICK", 2: "REINCARNATE", 3: "TICKET", 4: "CLAIM", 5: "HOLD"}

SBOX = {0x17: 1, 0x2a: 2, 0x3d: 3, 0x4e: 4, 0x5b: 5}
SBOX_INV = {v: k for k, v in SBOX.items()}

HI = [0x6, 0x2, 0x9, 0xc, 0x5, 0xa, 0x3, 0xf,
      0x1, 0x9, 0x4, 0xe, 0x8, 0x5, 0xd, 0x0]
LO = [0xb, 0xe, 0x1, 0x4, 0x7, 0x8, 0xd, 0x0,
      0xc, 0xb, 0x4, 0x7, 0x2, 0xa, 0x6, 0xf]


def vault_salt():
    return bytes((h << 4) | l for h, l in zip(HI, LO))


def decode_schedule(cid, sched_hex):
    salt = vault_salt()
    key = hashlib.sha256(salt + cid.encode()).digest()
    cipher = bytes.fromhex(sched_hex)
    plain = bytes(c ^ key[j % 32] for j, c in enumerate(cipher))
    n = plain[0]
    events = []
    for i in range(n):
        idx = plain[1 + i] ^ key[i % 32]
        events.append(SBOX[idx])
    return events


def encode_schedule(cid, events):
    salt = vault_salt()
    key = hashlib.sha256(salt + cid.encode()).digest()
    n = len(events)
    plain = bytearray(n + 1)
    plain[0] = n
    for i, evt in enumerate(events):
        idx = SBOX_INV[evt]
        plain[1 + i] = idx ^ key[i % 32]
    cipher = bytes(plain[j] ^ key[j % 32] for j in range(len(plain)))
    return cipher.hex()


def derive_nonce(salt, cid, nonce_idx):
    material = salt + cid.encode() + b"|" + str(nonce_idx).encode()
    return hashlib.sha256(material).digest()[:8].hex()


def issue_ticket(key, salt, cid, slot, gen, nonce_idx):
    nonce = derive_nonce(salt, cid, nonce_idx)
    material = (key + b"|ticket|" +
                f"{slot}|{gen}|{nonce}".encode() + salt)
    return hashlib.sha256(material).digest()[:16]


def vault_keystream(key, salt, slot, gen, scope, ticket):
    ticket_hex = ticket.hex()
    material = (key + b"|" +
                f"{slot}|{gen}|{scope}|{ticket_hex}|open".encode() + salt)
    return hashlib.sha256(material).digest()


def simulate(case, events):
    salt = vault_salt()
    key = bytes.fromhex(case["key_hex"])
    slot = case["slot"]
    gen = case["gen"]
    scope = case["scope"]
    nonce_idx = 0
    ticket = None

    for evt in events:
        if evt == EVT_TICK:
            gen += 1
        elif evt == EVT_REINCARNATE:
            gen += 1
            nonce_idx += 1
            ticket = None
        elif evt == EVT_TICKET:
            ticket = issue_ticket(key, salt, case["challenge_id"], slot, gen, nonce_idx)
        elif evt == EVT_CLAIM:
            if ticket is None:
                raise RuntimeError("no ticket at claim")
            ks = vault_keystream(key, salt, slot, gen, scope, ticket)
            return gen, ticket, ks
        elif evt == EVT_HOLD:
            pass
    raise RuntimeError("no claim in schedule")


def main():
    base = "/home/knoxj/assessment/dynamo-b24a90a-security/task"
    target = "echo"

    print("=== Current work schedules ===")
    work_dir = os.path.join(base, "environment/data/work")
    for name in sorted(os.listdir(work_dir)):
        cpath = os.path.join(work_dir, name, "case.json")
        if not os.path.isfile(cpath):
            continue
        with open(cpath) as f:
            case = json.load(f)
        events = decode_schedule(case["challenge_id"], case["sched_hex"])
        print(f"  {name}: {[EVT_NAMES[e] for e in events]}")

    # Reshuffle target: insert TICK at position 0
    work_case_path = os.path.join(work_dir, target, "case.json")
    with open(work_case_path) as f:
        case = json.load(f)

    old_events = decode_schedule(case["challenge_id"], case["sched_hex"])
    print(f"\n=== Reshuffling {target} ===")
    print(f"  Old schedule: {[EVT_NAMES[e] for e in old_events]}")

    # Insert TICK at beginning
    new_events = [EVT_TICK] + old_events
    print(f"  New schedule: {[EVT_NAMES[e] for e in new_events]}")

    new_sched_hex = encode_schedule(case["challenge_id"], new_events)
    print(f"  New sched_hex: {new_sched_hex}")

    # Verify decode round-trips
    rt = decode_schedule(case["challenge_id"], new_sched_hex)
    assert rt == new_events, f"round-trip failed: {rt} != {new_events}"

    # Get original flag from test inputs
    test_path = os.path.join(base, "tests/inputs", target, "case.json")
    with open(test_path) as f:
        test_case = json.load(f)
    real_flag = test_case["real_flag"]
    print(f"  Real flag: {real_flag}")

    # Simulate with new schedule to get new keystream
    gen_at_claim, ticket_at_claim, new_ks = simulate(case, new_events)
    print(f"  Gen at claim: {gen_at_claim}")
    print(f"  Ticket at claim: {ticket_at_claim.hex()}")

    # Compute new vault_blob_hex
    flag_bytes = real_flag.encode("utf-8")
    new_blob = bytes(flag_bytes[i] ^ new_ks[i % 32] for i in range(len(flag_bytes)))
    new_blob_hex = new_blob.hex()
    print(f"  New vault_blob_hex: {new_blob_hex}")

    # Verify: decrypt with new keystream should give original flag
    verify = bytes(new_blob[i] ^ new_ks[i % 32] for i in range(len(new_blob)))
    assert verify.decode("utf-8") == real_flag, "decrypt verification failed"

    # Update work case.json
    case["sched_hex"] = new_sched_hex
    case["vault_blob_hex"] = new_blob_hex
    with open(work_case_path, "w") as f:
        json.dump(case, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"\n  Updated {work_case_path}")

    # Update test inputs case.json
    test_case["sched_hex"] = new_sched_hex
    test_case["vault_blob_hex"] = new_blob_hex
    with open(test_path, "w") as f:
        json.dump(test_case, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"  Updated {test_path}")

    # Print verification
    print("\n=== Verification ===")
    verify_events = decode_schedule(case["challenge_id"], new_sched_hex)
    print(f"  Decoded new schedule: {[EVT_NAMES[e] for e in verify_events]}")
    gen2, ticket2, ks2 = simulate(case, verify_events)
    decrypted = bytes(new_blob[i] ^ ks2[i % 32] for i in range(len(new_blob)))
    print(f"  Decrypted flag: {decrypted.decode('utf-8')}")
    print(f"  Matches real_flag: {decrypted.decode('utf-8') == real_flag}")

    print("\nDone!")


if __name__ == "__main__":
    main()
