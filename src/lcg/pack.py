"""Step 6 of the pipeline: write the shippable compliance package."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from lcg import collect
from lcg.config import load_decisions, load_policy
from lcg.evaluate import evaluate
from lcg.models import ComplianceReport, Finding, FindingCode, Policy, ResolvedComponent, Severity
from lcg.resolve import resolve
from lcg.sbom import components_of, load_sbom, parse_document
from lcg.version import __version__

_ENV = Environment(
    loader=PackageLoader("lcg", "templates"),
    autoescape=select_autoescape(["html"]),
    trim_blocks=True,
    lstrip_blocks=True,
)


@dataclass(slots=True)
class PackInputs:
    """Everything the generator reads."""

    sbom: Path
    policy: Path
    decisions: Path | None = None
    license_texts: Path | None = None
    notices: Path | None = None


@dataclass(slots=True)
class PackResult:
    report: ComplianceReport
    output_dir: Path
    files: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return self.report.passed


def build_package(inputs: PackInputs, output_dir: Path) -> PackResult:
    """Run the whole pipeline and write the package to ``output_dir``."""
    document, sbom_sha256 = load_sbom(inputs.sbom)
    policy = load_policy(inputs.policy)
    decisions = load_decisions(inputs.decisions)
    return _build(
        document=document,
        sbom_bytes=inputs.sbom.read_bytes(),
        sbom_sha256=sbom_sha256,
        policy=policy,
        decisions_source=decisions,
        license_texts=inputs.license_texts,
        notices=inputs.notices,
        output_dir=output_dir,
    )


def build_package_from_data(
    sbom_document: Any,
    policy: Policy,
    decisions_source: list[Any],
    output_dir: Path,
) -> PackResult:
    """Same pipeline for in-memory input (used by the HTTP service)."""
    document = parse_document(sbom_document)
    sbom_bytes = json.dumps(document, indent=2, sort_keys=True).encode("utf-8")
    return _build(
        document=document,
        sbom_bytes=sbom_bytes,
        sbom_sha256=hashlib.sha256(sbom_bytes).hexdigest(),
        policy=policy,
        decisions_source=decisions_source,
        license_texts=None,
        notices=None,
        output_dir=output_dir,
    )


def _build(
    document: dict[str, Any],
    sbom_bytes: bytes,
    sbom_sha256: str,
    policy: Policy,
    decisions_source: list[Any],
    license_texts: Path | None,
    notices: Path | None,
    output_dir: Path,
) -> PackResult:
    components = components_of(document)
    resolved = resolve(components, list(decisions_source))
    report = evaluate(resolved, policy, sbom_sha256=sbom_sha256)

    texts = _gather_license_texts(resolved, policy, license_texts, report)
    attributions = _gather_attributions(resolved, policy, notices, report)

    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "licenses").mkdir(exist_ok=True)

    written: list[str] = [
        _write(output_dir, "sbom.cdx.json", sbom_bytes.decode("utf-8")),
        _write(
            output_dir,
            "sbom.enriched.cdx.json",
            json.dumps(_enrich(document, resolved), indent=2) + "\n",
        ),
    ]
    for file_name, text in sorted(texts.items()):
        written.append(_write(output_dir, f"licenses/{file_name}", text))
    written.append(
        _write(
            output_dir,
            "THIRD-PARTY-NOTICES.md",
            _render("notices.md.j2", report=report, attributions=attributions),
        )
    )
    written.append(_write(output_dir, "decisions.md", _render("decisions.md.j2", report=report)))
    written.append(
        _write(output_dir, "compliance-report.json", report.model_dump_json(indent=2) + "\n")
    )
    written.append(
        _write(
            output_dir,
            "compliance-report.html",
            _render("report.html.j2", report=report, attributions=attributions),
        )
    )
    written.append(
        _write(
            output_dir,
            "manifest.json",
            json.dumps(_manifest(output_dir, written, report), indent=2) + "\n",
        )
    )
    return PackResult(report=report, output_dir=output_dir, files=sorted(written))


def _gather_license_texts(
    resolved: list[ResolvedComponent],
    policy: Policy,
    texts_dir: Path | None,
    report: ComplianceReport,
) -> dict[str, str]:
    texts: dict[str, str] = {}
    for item in resolved:
        for license_id in item.effective_licenses:
            rule = policy.license_rule(license_id)
            if rule is not None and not rule.requires_license_text:
                continue
            text = collect.find_license_text(license_id, item, texts_dir)
            if text:
                texts[f"{collect.safe_name(license_id)}.txt"] = text
            elif policy.require_license_texts:
                report.findings.append(
                    Finding(
                        code=FindingCode.LICENSE_TEXT_MISSING,
                        severity=Severity.ERROR,
                        component=item.component.key,
                        message=f"No license text available for {license_id}.",
                        hint="Put the text into the license-texts directory.",
                    )
                )
    return texts


def _gather_attributions(
    resolved: list[ResolvedComponent],
    policy: Policy,
    notices_dir: Path | None,
    report: ComplianceReport,
) -> dict[str, str]:
    attributions: dict[str, str] = {}
    for item in resolved:
        attribution = collect.find_attribution(item, notices_dir)
        if attribution:
            attributions[item.component.key] = attribution
            continue
        needs_notice = any(
            (rule := policy.license_rule(license_id)) is not None and rule.requires_notice
            for license_id in item.effective_licenses
        )
        if policy.require_attributions and needs_notice:
            report.findings.append(
                Finding(
                    code=FindingCode.ATTRIBUTION_MISSING,
                    severity=Severity.WARNING,
                    component=item.component.key,
                    message=f"No attribution found for {item.component.display}.",
                    hint="Add a copyright to the SBOM or a file in the notices directory.",
                )
            )
    return attributions


def _enrich(document: dict[str, Any], resolved: list[ResolvedComponent]) -> dict[str, Any]:
    """Annotate the SBOM with the effective licenses and decision references."""
    by_key = {item.component.key: item for item in resolved}
    enriched: dict[str, Any] = json.loads(json.dumps(document))
    for entry in _iter_components(enriched.get("components", [])):
        key = entry.get("purl") or f"{entry.get('name', '')}@{entry.get('version', '')}".rstrip("@")
        item = by_key.get(key) or by_key.get(str(entry.get("name", "")))
        if item is None:
            continue
        properties = entry.setdefault("properties", [])
        properties.append(
            {"name": "lcg:effective-licenses", "value": " AND ".join(item.effective_licenses)}
        )
        if item.decision is not None:
            properties.append({"name": "lcg:decision", "value": item.decision.chosen})
            if item.decision.rationale:
                properties.append(
                    {"name": "lcg:decision-rationale", "value": item.decision.rationale}
                )
    return enriched


def _iter_components(entries: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if not isinstance(entries, list):
        return found
    for entry in entries:
        if isinstance(entry, dict):
            found.append(entry)
            found.extend(_iter_components(entry.get("components", [])))
    return found


def _manifest(output_dir: Path, files: list[str], report: ComplianceReport) -> dict[str, Any]:
    """The evidence: hashes of every file plus the versions that produced them."""
    return {
        "tool": "license-compliance-gateway",
        "tool_version": __version__,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "policy": {"name": report.policy_name, "version": report.policy_version},
        "sbom_sha256": report.sbom_sha256,
        "result": "passed" if report.passed else "failed",
        "error_count": len(report.errors),
        "warning_count": len(report.warnings),
        "files": {
            name: hashlib.sha256((output_dir / name).read_bytes()).hexdigest()
            for name in sorted(files)
        },
    }


def _render(template: str, **context: Any) -> str:
    return _ENV.get_template(template).render(**context)


def _write(output_dir: Path, relative_path: str, content: str) -> str:
    path = output_dir / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return relative_path
