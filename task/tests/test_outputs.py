"""Graded tests for RingVault (no oracle imports)."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path

import pytest

ARTIFACT = "/app/output/flags.json"
SEAL_PATH = "/logs/verifier/sealed_expectations.json"


@pytest.fixture(scope="session")
def sealed():
    """Load sealed expectations from phase A."""
    return json.loads(Path(SEAL_PATH).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def expected_document(sealed):
    """Decode sealed expected document text."""
    return base64.b64decode(sealed["expected_document_b64"]).decode("utf-8")


@pytest.fixture(scope="session")
def agent_raw():
    """Read agent output as text."""
    return Path(ARTIFACT).read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def agent_data(agent_raw):
    """Parse agent output JSON."""
    return json.loads(agent_raw)


def test_ordinary_file():
    """Criterion 1: output exists as an ordinary file not a symlink."""
    path = Path(ARTIFACT)
    assert path.exists()
    assert not path.is_symlink()
    assert path.is_file()
    assert os.path.isfile(ARTIFACT)


def test_schema_key_order(agent_data):
    """Criterion 2: challenges array with keys id then flag."""
    assert list(agent_data.keys()) == ["challenges"]
    for row in agent_data["challenges"]:
        assert list(row.keys()) == ["id", "flag"]


def test_sorted_work_ids(agent_data, sealed):
    """Criterion 3: ids sorted ascending covering every work case."""
    ids = [r["id"] for r in agent_data["challenges"]]
    assert ids == sealed["work_ids"]
    assert ids == sorted(ids)
    assert "alpha" not in ids


def test_byte_exact_formatting(agent_raw, expected_document):
    """Criterion 4: serialized bytes match BRIEF formatting and sealed expected."""
    assert agent_raw == expected_document


def test_flags_match_vault_rules(agent_data, expected_document):
    """Criterion 5: each work flag matches sealed vault release."""
    assert agent_data == json.loads(expected_document)


def test_wrong_models_diverge(agent_raw, sealed):
    """Wrong-model contrast: naive residues differ from expected."""
    got = hashlib.sha256(agent_raw.encode("utf-8")).hexdigest()
    for name, digest in sealed["wrong_model_residues"].items():
        assert got != digest, name
