#!/usr/bin/env python3
"""Oracle solver for Mesh Claim CTF."""

from __future__ import annotations

import hashlib
import json
import os


def resolve_name(name: str, aliases: dict[str, str]) -> str:
    """Follow alias chains until stable."""
    seen: set[str] = set()
    while name in aliases and name not in seen:
        seen.add(name)
        name = aliases[name]
    return name


def interpret_ledger(ledger_path: str, start_id: str):
    """Process ledger ops and return (terminal_id, walk_edge_ids)."""
    nodes: dict[str, str] = {}
    edges: dict[str, tuple[str, str]] = {}
    sinks: set[str] = set()
    aliases: dict[str, str] = {}
    cut_nodes: set[str] = set()
    revoked_edges: set[str] = set()

    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            op = json.loads(line)
            kind = op["op"]

            if kind == "NODE":
                nodes[op["id"]] = op["body"]
            elif kind == "EDGE":
                edges[op["id"]] = (op["src"], op["dst"])
            elif kind == "CUT":
                target = resolve_name(op["target"], aliases)
                cut_nodes.add(target)
                for eid, (s, d) in list(edges.items()):
                    if resolve_name(s, aliases) == target or resolve_name(d, aliases) == target:
                        revoked_edges.add(eid)
            elif kind == "FORK":
                src = resolve_name(op["src"], aliases)
                dst = op["dst"]
                if src in nodes:
                    nodes[dst] = nodes[src]
                cut_nodes.add(src)
                for eid, (s, d) in list(edges.items()):
                    if resolve_name(s, aliases) == src or resolve_name(d, aliases) == src:
                        revoked_edges.add(eid)
            elif kind == "ALIAS":
                aliases[op["old"]] = op["new"]
            elif kind == "REVOKE":
                revoked_edges.add(op["target"])
            elif kind == "SINK":
                sinks.add(resolve_name(op["node"], aliases))

    live_edges: dict[str, tuple[str, str]] = {}
    for eid, (src, dst) in edges.items():
        if eid in revoked_edges:
            continue
        rs = resolve_name(src, aliases)
        rd = resolve_name(dst, aliases)
        if rs in cut_nodes or rd in cut_nodes:
            continue
        live_edges[eid] = (rs, rd)

    start = resolve_name(start_id, aliases)
    adj: dict[str, list[tuple[str, str]]] = {}
    for eid, (src, dst) in live_edges.items():
        adj.setdefault(src, []).append((eid, dst))

    reachable: set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in reachable:
            continue
        reachable.add(node)
        for _, dst in adj.get(node, []):
            stack.append(dst)

    live_sinks = [s for s in sinks if s in reachable and s not in cut_nodes]
    if not live_sinks:
        raise ValueError("No reachable live SINK nodes")
    terminal = max(live_sinks)

    for node in adj:
        adj[node].sort(key=lambda x: x[0])

    path_edges: list[str] = []
    current = start
    visited: set[str] = set()
    while current != terminal:
        if current in visited:
            raise ValueError(f"Cycle at {current}")
        visited.add(current)
        if current not in adj:
            raise ValueError(f"Dead end at {current}")
        eid, dst = adj[current][0]
        path_edges.append(eid)
        current = dst

    return terminal, path_edges


def compute_walk_hex(edge_ids: list[str]) -> str:
    joined = "|".join(edge_ids)
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def compute_claim_seal(key_bytes: bytes, slot: int, terminal_id: str,
                       scope: str, nonce: str, walk_hex: str) -> bytes:
    material = f"{slot}|{terminal_id}|{scope}|{nonce}|{walk_hex}|open"
    return hashlib.sha256(key_bytes + b"|" + material.encode("utf-8")).digest()


def decrypt_flag(vault_blob_hex: str, keystream: bytes) -> str:
    vault = bytes.fromhex(vault_blob_hex)
    flag_bytes = bytearray(len(vault))
    for i in range(len(vault)):
        flag_bytes[i] = vault[i] ^ keystream[i % 32]
    return flag_bytes.decode("utf-8")


def solve_case(case_dir: str) -> tuple[str, str]:
    case_path = os.path.join(case_dir, "case.json")
    ledger_path = os.path.join(case_dir, "ledger.jsonl")

    with open(case_path, encoding="utf-8") as f:
        case = json.load(f)

    key_bytes = bytes.fromhex(case["key_hex"])
    terminal, walk_edges = interpret_ledger(ledger_path, case["start_id"])
    walk_hex = compute_walk_hex(walk_edges)
    keystream = compute_claim_seal(
        key_bytes, case["slot"], terminal, case["scope"], case["nonce"], walk_hex,
    )
    flag = decrypt_flag(case["vault_blob_hex"], keystream)
    return case["challenge_id"], flag


def main() -> None:
    work_dir = "/app/data/work"
    results = []
    for name in sorted(os.listdir(work_dir)):
        case_path = os.path.join(work_dir, name)
        if not os.path.isdir(case_path):
            continue
        if not os.path.isfile(os.path.join(case_path, "case.json")):
            continue
        cid, flag = solve_case(case_path)
        results.append({"id": cid, "flag": flag})
        print(f"  {cid}: {flag}")

    results.sort(key=lambda x: x["id"])
    output = {"challenges": results}
    os.makedirs("/app/output", exist_ok=True)
    with open("/app/output/flags.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"Wrote {len(results)} flags to /app/output/flags.json")


if __name__ == "__main__":
    main()
