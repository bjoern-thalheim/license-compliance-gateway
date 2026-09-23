"""Stateless HTTP service.

Nothing is persisted: each request builds the package in a temporary directory
that is removed before the response is returned, so the service can be scaled
horizontally in Kubernetes.
"""

from __future__ import annotations

import io
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field

from lcg.models import ComplianceReport, Decision, Policy
from lcg.pack import PackResult, build_package_from_data
from lcg.sbom import SbomError
from lcg.version import __version__

app = FastAPI(title="License Compliance Gateway", version=__version__)


class PackageRequest(BaseModel):
    sbom: dict[str, Any] = Field(description="CycloneDX-Dokument als JSON.")
    policy: Policy
    decisions: list[Decision] = Field(default_factory=list)


class CheckResponse(BaseModel):
    passed: bool
    report: ComplianceReport


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/v1/check", response_model=CheckResponse)
def check(request: PackageRequest) -> CheckResponse:
    """Prüft eine SBOM und liefert den maschinenlesbaren Report."""
    result = _build(request)
    return CheckResponse(passed=result.passed, report=result.report)


@app.post(
    "/v1/package",
    responses={200: {"content": {"application/zip": {}}}},
    response_class=Response,
)
def package(request: PackageRequest) -> Response:
    """Liefert das vollständige Compliance-Paket als ZIP."""
    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp) / "compliance"
        result = _build(request, output_dir=output_dir)
        archive = _zip(output_dir)
    return Response(
        content=archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="compliance-package.zip"',
            "X-Compliance-Result": "passed" if result.passed else "failed",
        },
    )


def _build(request: PackageRequest, output_dir: Path | None = None) -> PackResult:
    if output_dir is None:
        with tempfile.TemporaryDirectory() as tmp:
            return _build(request, output_dir=Path(tmp) / "compliance")
    try:
        return build_package_from_data(
            sbom_document=request.sbom,
            policy=request.policy,
            decisions_source=list(request.decisions),
            output_dir=output_dir,
        )
    except SbomError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _zip(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(directory).as_posix())
    return buffer.getvalue()
