"""Step 4 of the pipeline: apply the policy and collect findings."""

from __future__ import annotations

from datetime import UTC, datetime

from lcg import licenses
from lcg.models import (
    ComplianceReport,
    Finding,
    FindingCode,
    Policy,
    ResolvedComponent,
    Severity,
)
from lcg.version import __version__


def evaluate(
    resolved: list[ResolvedComponent],
    policy: Policy,
    sbom_sha256: str = "",
) -> ComplianceReport:
    findings: list[Finding] = []
    for item in resolved:
        findings.extend(_check_component(item, policy))
    return ComplianceReport(
        policy_name=policy.name,
        policy_version=policy.version,
        tool_version=__version__,
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        sbom_sha256=sbom_sha256,
        components=resolved,
        findings=findings,
    )


def _check_component(item: ResolvedComponent, policy: Policy) -> list[Finding]:
    component = item.component
    key = component.key

    for rule in policy.denied_components:
        if rule.matches(component):
            return [
                Finding(
                    code=FindingCode.COMPONENT_DENIED,
                    severity=Severity.ERROR,
                    component=key,
                    message=f"{component.display} is on the component denylist.",
                    hint=rule.note,
                )
            ]

    allowance = next((r for r in policy.allowed_components if r.matches(component)), None)
    if allowance is not None:
        return []

    findings = _check_expression(item, policy)
    findings.extend(_check_decision(item))
    findings.extend(_check_effective_licenses(item, policy))
    return findings


def _check_expression(item: ResolvedComponent, policy: Policy) -> list[Finding]:
    component = item.component
    if not component.license_expression.strip():
        return [
            Finding(
                code=FindingCode.LICENSE_MISSING,
                severity=policy.unknown_license_severity,
                component=component.key,
                message=f"{component.display} declares no license in the SBOM.",
                hint="Add the license to the SBOM or allow the component explicitly.",
            )
        ]
    if not item.normalized_expression:
        return [
            Finding(
                code=FindingCode.LICENSE_UNPARSEABLE,
                severity=policy.unknown_license_severity,
                component=component.key,
                message=(
                    f"{component.display} has an unparseable license expression "
                    f"{component.license_expression!r}."
                ),
                hint="Add an alias mapping or record a decision for this component.",
            )
        ]
    return []


def _check_decision(item: ResolvedComponent) -> list[Finding]:
    component = item.component
    if item.needs_decision:
        return [
            Finding(
                code=FindingCode.DECISION_REQUIRED,
                severity=Severity.ERROR,
                component=component.key,
                message=(
                    f"{component.display} is multi-licensed "
                    f"({item.normalized_expression}) and needs a documented decision."
                ),
                hint="Add a decision file with the chosen license and a rationale.",
            )
        ]

    decision = item.decision
    if decision is None:
        return []

    findings: list[Finding] = []
    if decision.expression and _differs(decision.expression, item.normalized_expression):
        findings.append(
            Finding(
                code=FindingCode.DECISION_STALE,
                severity=Severity.ERROR,
                component=component.key,
                message=(
                    f"The decision for {component.display} was made for "
                    f"{decision.expression!r} but the SBOM now declares "
                    f"{item.normalized_expression!r}."
                ),
                hint="Review the decision and update it.",
            )
        )
    if not _is_offered(decision.chosen, item.normalized_expression):
        findings.append(
            Finding(
                code=FindingCode.DECISION_INVALID_CHOICE,
                severity=Severity.ERROR,
                component=component.key,
                message=(
                    f"The chosen license {decision.chosen!r} is not part of "
                    f"{item.normalized_expression!r}."
                ),
            )
        )
    return findings


def _check_effective_licenses(item: ResolvedComponent, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for license_id in item.effective_licenses:
        if policy.is_denied_license(license_id):
            findings.append(
                Finding(
                    code=FindingCode.LICENSE_DENIED,
                    severity=Severity.ERROR,
                    component=item.component.key,
                    message=f"{item.component.display}: license {license_id} is denied.",
                )
            )
            continue
        if policy.license_rule(license_id) is None:
            findings.append(
                Finding(
                    code=FindingCode.LICENSE_NOT_ALLOWED,
                    severity=policy.unknown_license_severity,
                    component=item.component.key,
                    message=(
                        f"{item.component.display}: license {license_id} is not on the whitelist."
                    ),
                    hint="Add it to allowed_licenses or allow the component explicitly.",
                )
            )
    return findings


def _differs(recorded: str, current: str) -> bool:
    try:
        return licenses.normalize(recorded) != current
    except licenses.LicenseExpressionError:
        return True


def _is_offered(chosen: str, expression: str) -> bool:
    try:
        offered = {i.lower() for i in licenses.license_ids(expression)}
        return all(i.lower() in offered for i in licenses.license_ids(chosen))
    except licenses.LicenseExpressionError:
        return False
