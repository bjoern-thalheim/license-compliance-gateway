from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from lcg.evaluate import evaluate
from lcg.models import Component, Decision, FindingCode, LicenseRule, Policy, Severity
from lcg.pack import PackInputs, build_package
from lcg.resolve import resolve
from lcg.sbom import components_of


def _decision(**overrides: Any) -> Decision:
    base: dict[str, Any] = {
        "component": "pkg:pypi/dual-licensed-lib@2.1.0",
        "expression": "MIT OR Apache-2.0",
        "chosen": "MIT",
        "rationale": "Ausreichend für proprietäre Auslieferung.",
        "decided_by": "test",
    }
    return Decision.model_validate(base | overrides)


def test_components_are_parsed(example_sbom: dict[str, Any]) -> None:
    components = components_of(example_sbom)
    assert [c.name for c in components] == [
        "simple-lib",
        "dual-licensed-lib",
        "combined-lib",
        "legacy-lib",
    ]
    assert components[2].license_expression == "MIT AND BSD-3-Clause"


def test_choice_without_decision_is_an_error(
    example_sbom: dict[str, Any], example_policy: Policy
) -> None:
    resolved = resolve(components_of(example_sbom), [])
    report = evaluate(resolved, example_policy)
    codes = {f.code for f in report.findings}
    assert FindingCode.DECISION_REQUIRED in codes
    assert not report.passed


def test_decision_resolves_the_choice(example_sbom: dict[str, Any], example_policy: Policy) -> None:
    resolved = resolve(components_of(example_sbom), [_decision()])
    report = evaluate(resolved, example_policy)
    dual = next(i for i in report.components if i.component.name == "dual-licensed-lib")
    assert dual.effective_licenses == ["MIT"]
    assert not [f for f in report.findings if f.code is FindingCode.DECISION_REQUIRED]


def test_stale_decision_is_detected(example_policy: Policy) -> None:
    component = Component(
        name="dual-licensed-lib",
        version="2.1.0",
        purl="pkg:pypi/dual-licensed-lib@2.1.0",
        license_expression="MIT OR BSD-3-Clause",
    )
    resolved = resolve([component], [_decision()])
    report = evaluate(resolved, example_policy)
    assert FindingCode.DECISION_STALE in {f.code for f in report.findings}


def test_choice_outside_the_expression_is_rejected(example_policy: Policy) -> None:
    component = Component(
        name="dual-licensed-lib",
        version="2.1.0",
        purl="pkg:pypi/dual-licensed-lib@2.1.0",
        license_expression="MIT OR Apache-2.0",
    )
    resolved = resolve([component], [_decision(chosen="ISC", expression="")])
    report = evaluate(resolved, example_policy)
    assert FindingCode.DECISION_INVALID_CHOICE in {f.code for f in report.findings}


def test_denied_license_beats_whitelist() -> None:
    policy = Policy(
        allowed_licenses=[LicenseRule(id="AGPL-3.0-only")],
        denied_licenses=["AGPL-3.0-only"],
        require_license_texts=False,
    )
    component = Component(name="copyleft-lib", version="1.0", license_expression="AGPL-3.0-only")
    report = evaluate(resolve([component], []), policy)
    assert FindingCode.LICENSE_DENIED in {f.code for f in report.findings}


def test_copyleft_passes_when_whitelisted() -> None:
    policy = Policy(
        allowed_licenses=[LicenseRule(id="GPL-3.0-only")],
        require_license_texts=False,
    )
    component = Component(name="copyleft-lib", version="1.0", license_expression="GPL-3.0-only")
    report = evaluate(resolve([component], []), policy)
    assert report.passed


def test_component_allowance_skips_license_checks() -> None:
    policy = Policy.model_validate(
        {
            "allowed_licenses": [],
            "allowed_components": [{"match": "pkg:npm/@acme/*", "note": "Interner Code"}],
        }
    )
    component = Component(
        name="widget",
        version="1.0",
        purl="pkg:npm/@acme/widget@1.0",
        license_expression="Proprietary",
    )
    report = evaluate(resolve([component], []), policy)
    assert report.passed


def test_missing_license_severity_is_configurable() -> None:
    component = Component(name="mystery", version="1.0")
    strict = evaluate(resolve([component], []), Policy(require_license_texts=False))
    lenient = evaluate(
        resolve([component], []),
        Policy(unknown_license_severity=Severity.WARNING, require_license_texts=False),
    )
    assert not strict.passed
    assert lenient.passed
    assert FindingCode.LICENSE_MISSING in {f.code for f in lenient.findings}


def test_build_package_writes_all_artifacts(
    tmp_path: Path,
    sbom_path: Path,
    policy_path: Path,
    decisions_path: Path,
    license_texts_path: Path,
) -> None:
    result = build_package(
        PackInputs(
            sbom=sbom_path,
            policy=policy_path,
            decisions=decisions_path,
            license_texts=license_texts_path,
        ),
        tmp_path / "compliance",
    )

    expected = {
        "sbom.cdx.json",
        "sbom.enriched.cdx.json",
        "THIRD-PARTY-NOTICES.md",
        "decisions.md",
        "compliance-report.json",
        "compliance-report.html",
        "manifest.json",
        "licenses/MIT.txt",
        "licenses/BSD-3-Clause.txt",
    }
    assert expected <= set(result.files)

    manifest = json.loads((result.output_dir / "manifest.json").read_text("utf-8"))
    assert manifest["sbom_sha256"] == result.report.sbom_sha256
    assert set(manifest["files"]) <= set(result.files)

    notices = (result.output_dir / "THIRD-PARTY-NOTICES.md").read_text("utf-8")
    assert "Copyright (c) 2024 Simple Lib Authors" in notices

    decisions_doc = (result.output_dir / "decisions.md").read_text("utf-8")
    assert "dual-licensed-lib" in decisions_doc

    enriched = json.loads((result.output_dir / "sbom.enriched.cdx.json").read_text("utf-8"))
    dual = next(c for c in enriched["components"] if c["name"] == "dual-licensed-lib")
    assert {"name": "lcg:decision", "value": "MIT"} in dual["properties"]


def test_example_package_reports_missing_attribution(
    tmp_path: Path,
    sbom_path: Path,
    policy_path: Path,
    decisions_path: Path,
    license_texts_path: Path,
) -> None:
    result = build_package(
        PackInputs(
            sbom=sbom_path,
            policy=policy_path,
            decisions=decisions_path,
            license_texts=license_texts_path,
        ),
        tmp_path / "compliance",
    )
    codes = {f.code for f in result.report.findings}
    assert codes == {FindingCode.ATTRIBUTION_MISSING}
    assert result.passed
