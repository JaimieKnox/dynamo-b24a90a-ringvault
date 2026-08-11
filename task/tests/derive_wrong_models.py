"""Wrong-model residues for RingVault."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def format_output(flags: dict[str, str]) -> str:
    rows = [{"id": k, "flag": flags[k]} for k in sorted(flags)]
    return json.dumps({"challenges": rows}, indent=2, ensure_ascii=False) + "\n"


def all_wrong_model_residues(work_dir: str) -> dict[str, str]:
    work = Path(work_dir)
    decoys: dict[str, str] = {}
    short_gen: dict[str, str] = {}
    for case_dir in sorted(p for p in work.iterdir() if p.is_dir()):
        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        decoys[case_dir.name] = case["decoy_flag"]
        # wrong-gen / truncated path also yields decoy on these fixtures
        short_gen[case_dir.name] = case["decoy_flag"]
    return {
        "naive_short_flat": hashlib.sha256(format_output(decoys).encode()).hexdigest(),
        "wrong_gen": hashlib.sha256(format_output(short_gen).encode()).hexdigest(),
    }
