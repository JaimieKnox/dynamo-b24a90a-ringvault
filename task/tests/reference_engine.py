"""Independent reference capture for RingVault (verify-time only)."""

from __future__ import annotations

import json
from pathlib import Path


def capture_all_work_flags() -> dict[str, str]:
    """Return id->real_flag from sealed tests/inputs mirrors (not agent-writable /app)."""
    root = Path("/tests/inputs")
    work = Path("/app/data/work")
    out: dict[str, str] = {}
    for case_dir in sorted(p for p in work.iterdir() if p.is_dir()):
        mirror = root / case_dir.name / "case.json"
        case = json.loads(mirror.read_text(encoding="utf-8"))
        out[case_dir.name] = case["real_flag"]
    return out
