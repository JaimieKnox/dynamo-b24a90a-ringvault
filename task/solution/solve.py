#!/usr/bin/env python3
"""
Oracle solution for RingVault CTF.

For each work case, traces reincarnation events to determine the final
session generation, constructs a properly nested TLV claim with a
full-width seal tag, and extracts the real flag from the vault reply.
"""

import hashlib
import json
import os
import struct
import sys

TYPE_AUTH = 0x01
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05


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


def compute_full_tag(key_bytes, slot, gen, scope, nonce, tag_len=16):
    material = f"{slot}|{gen}|{scope}|{nonce}".encode()
    full = hashlib.sha256(key_bytes + b"|" + material).digest()
    return full[:tag_len]


def wrap_nested(inner_body, depth):
    current = inner_body
    for _ in range(depth):
        current = encode_tlv(TYPE_NEST, current)
    return current


def solve_case(case_dir):
    sys.path.insert(0, "/app/data")
    from ringvault.lab import Lab

    with open(os.path.join(case_dir, "case.json")) as f:
        case = json.load(f)

    lab = Lab(case_dir)

    key = bytes.fromhex(case["key_hex"])
    slot = case["slot"]
    gen = case["gen"]
    scope = case["scope"]
    nonce = case["nonce"]
    nest_required = case["nest_required"]
    script = case["script"]

    final_gen = gen
    for event in script:
        if event == "reincarnate":
            final_gen += 1

    tag = compute_full_tag(key, slot, final_gen, scope, nonce, tag_len=16)

    auth_record = encode_tlv(TYPE_AUTH, tag)
    claim_record = encode_tlv(TYPE_CLAIM, scope.encode())
    inner = auth_record + claim_record

    body = wrap_nested(inner, nest_required)
    frame = encode_frame(body)

    reply_frame = lab.step(frame)
    reply_body = decode_frame(reply_frame)

    for typ, val in decode_tlvs(reply_body):
        if typ == TYPE_REPLY:
            return val.decode("utf-8")

    raise RuntimeError(f"No REPLY in response for {case['challenge_id']}")


def main():
    work_dir = "/app/data/work"
    results = []

    for case_name in sorted(os.listdir(work_dir)):
        case_path = os.path.join(work_dir, case_name)
        if not os.path.isdir(case_path):
            continue
        case_json_path = os.path.join(case_path, "case.json")
        if not os.path.isfile(case_json_path):
            continue

        flag = solve_case(case_path)
        results.append({"id": case_name, "flag": flag})
        print(f"  {case_name}: {flag}")

    results.sort(key=lambda x: x["id"])
    output = {"challenges": results}

    os.makedirs("/app/output", exist_ok=True)
    with open("/app/output/flags.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Wrote {len(results)} flags to /app/output/flags.json")


if __name__ == "__main__":
    main()
