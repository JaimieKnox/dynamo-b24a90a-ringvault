"""Independent reference capture for RingVault (verify-time only)."""

from __future__ import annotations

import json
from pathlib import Path


def capture_all_work_flags() -> dict[str, str]:
    """Return id->real_flag from sealed tests/inputs mirrors (not agent-writable /app)."""
    root = Path("/tests/inputs")
    out: dict[str, str] = {}
    for case_path in sorted(root.glob("*/case.json")):
        case = json.loads(case_path.read_text(encoding="utf-8"))
        out[case_path.parent.name] = case["real_flag"]
    return out
