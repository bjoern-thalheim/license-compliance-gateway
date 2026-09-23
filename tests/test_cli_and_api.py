from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lcg.api import app as api_app
from lcg.cli import app as cli_app
from lcg.models import Policy

runner = CliRunner()
client = TestClient(api_app)


def test_check_fails_without_decisions(sbom_path: Path, policy_path: Path) -> None:
    result = runner.invoke(cli_app, ["check", "-s", str(sbom_path), "-p", str(policy_path)])
    assert result.exit_code == 1
    assert "decision_required" in result.output


def test_check_passes_with_decisions(
    sbom_path: Path, policy_path: Path, decisions_path: Path
) -> None:
    result = runner.invoke(
        cli_app,
        ["check", "-s", str(sbom_path), "-p", str(policy_path), "-d", str(decisions_path)],
    )
    assert result.exit_code == 0


def test_build_writes_package(
    tmp_path: Path,
    sbom_path: Path,
    policy_path: Path,
    decisions_path: Path,
    license_texts_path: Path,
) -> None:
    output = tmp_path / "out"
    result = runner.invoke(
        cli_app,
        [
            "build",
            "-s",
            str(sbom_path),
            "-p",
            str(policy_path),
            "-d",
            str(decisions_path),
            "--license-texts",
            str(license_texts_path),
            "-o",
            str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (output / "compliance-report.html").is_file()


def test_api_check(example_sbom: dict[str, Any], example_policy: Policy) -> None:
    response = client.post(
        "/v1/check",
        json={
            "sbom": example_sbom,
            "policy": example_policy.model_dump(mode="json"),
            "decisions": [],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["passed"] is False
    codes = {f["code"] for f in body["report"]["findings"]}
    assert "decision_required" in codes


def test_api_package_returns_zip(example_sbom: dict[str, Any], example_policy: Policy) -> None:
    policy = example_policy.model_copy(update={"require_license_texts": False})
    response = client.post(
        "/v1/package",
        json={
            "sbom": example_sbom,
            "policy": policy.model_dump(mode="json"),
            "decisions": [
                {
                    "component": "pkg:pypi/dual-licensed-lib@2.1.0",
                    "expression": "MIT OR Apache-2.0",
                    "chosen": "MIT",
                    "decided_by": "test",
                }
            ],
        },
    )
    assert response.status_code == 200
    assert response.headers["x-compliance-result"] == "passed"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = set(archive.namelist())
        assert {"manifest.json", "compliance-report.html"} <= names
        manifest = json.loads(archive.read("manifest.json"))
    assert manifest["result"] == "passed"


def test_api_rejects_non_cyclonedx() -> None:
    response = client.post(
        "/v1/check",
        json={"sbom": {"bomFormat": "SPDX"}, "policy": {"name": "x"}, "decisions": []},
    )
    assert response.status_code == 422


def test_healthz() -> None:
    assert client.get("/healthz").json()["status"] == "ok"
