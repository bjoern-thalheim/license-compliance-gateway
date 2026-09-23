from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from lcg.models import Policy

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def example_sbom() -> dict[str, Any]:
    data: dict[str, Any] = json.loads((EXAMPLES / "sbom.cdx.json").read_text(encoding="utf-8"))
    return data


@pytest.fixture
def example_policy() -> Policy:
    return Policy.model_validate(yaml.safe_load((EXAMPLES / "policy.yaml").read_text("utf-8")))


@pytest.fixture
def sbom_path() -> Path:
    return EXAMPLES / "sbom.cdx.json"


@pytest.fixture
def policy_path() -> Path:
    return EXAMPLES / "policy.yaml"


@pytest.fixture
def decisions_path() -> Path:
    return EXAMPLES / "decisions"


@pytest.fixture
def license_texts_path() -> Path:
    return EXAMPLES / "license-texts"
