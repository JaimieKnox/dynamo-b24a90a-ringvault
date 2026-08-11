"""Phase A: seal expectations then get deleted by test.sh."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

from reference_engine import capture_all_work_flags
from derive_wrong_models import all_wrong_model_residues, format_output


def main() -> None:
    correct_flags = capture_all_work_flags()
    expected_doc = format_output(correct_flags)
    expected_hash = hashlib.sha256(expected_doc.encode("utf-8")).hexdigest()
    work_dir = "/app/data/work"
    wrong_residues = all_wrong_model_residues(work_dir)
    work_ids = sorted(
        name
        for name in os.listdir(work_dir)
        if os.path.isfile(os.path.join(work_dir, name, "case.json"))
    )
    seal = {
        "expected_document_b64": base64.b64encode(expected_doc.encode("utf-8")).decode("ascii"),
        "expected_hash": expected_hash,
        "wrong_model_residues": wrong_residues,
        "work_ids": work_ids,
    }
    out = Path("/logs/verifier/sealed_expectations.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(seal, indent=2) + "\n", encoding="utf-8")
    print(f"Sealed expectations written. {len(work_ids)} work cases.")


if __name__ == "__main__":
    main()
