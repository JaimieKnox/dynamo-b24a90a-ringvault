#!/usr/bin/env python3
"""Oracle solution for RingVault CTF."""

from __future__ import annotations

import json
import os
import struct
import sys

TYPE_AUTH = 0x01
TYPE_NOTE = 0x02
TYPE_NEST = 0x03
TYPE_CLAIM = 0x04
TYPE_REPLY = 0x05
TYPE_TICKET = 0x06


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


def solve_case(case_dir):
    sys.path.insert(0, "/app/data")
    from ringvault.lab import Lab
    import ringvault.seal as seal

    with open(os.path.join(case_dir, "case.json"), encoding="utf-8") as f:
        case = json.load(f)

    lab = Lab(case_dir)
    # Ticket request. Lab advances ticks/reincarnates before the ticket gate.
    ticket_reply = lab.step(encode_frame(encode_tlv(TYPE_NOTE, b"session")))
    ticket = None
    for typ, val in decode_tlvs(decode_frame(ticket_reply)):
        if typ == TYPE_TICKET:
            ticket = val
    if ticket is None:
        raise RuntimeError(f"no ticket for {case['challenge_id']}")

    material = seal.make_material(lab.slot, lab.gen, lab.scope, lab.nonce, ticket)
    tag = seal.compute_tag(lab.key, material)
    if case["nest_required"] == 0:
        tag = tag[:4]

    inner = (
        encode_tlv(TYPE_AUTH, tag)
        + encode_tlv(TYPE_CLAIM, case["scope"].encode())
        + encode_tlv(TYPE_TICKET, ticket)
    )
    body = wrap_nested(inner, case["nest_required"])
    reply_frame = lab.step(encode_frame(body))
    for typ, val in decode_tlvs(decode_frame(reply_frame)):
        if typ == TYPE_REPLY:
            return val.decode("utf-8")
    raise RuntimeError(f"No REPLY for {case['challenge_id']}")


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
