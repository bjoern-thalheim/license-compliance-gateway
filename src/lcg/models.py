"""Data model of the compliance gateway.

The whole pipeline is built around three kinds of input:

* the SBOM              -> :class:`Component`
* the policy            -> :class:`Policy`
* license decisions     -> :class:`Decision`

and produces one :class:`ComplianceReport`.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class FindingCode(StrEnum):
    """Every reason why a component can show up in the report."""

    LICENSE_MISSING = "license_missing"
    LICENSE_UNPARSEABLE = "license_unparseable"
    LICENSE_NOT_ALLOWED = "license_not_allowed"
    LICENSE_DENIED = "license_denied"
    COMPONENT_NOT_ALLOWED = "component_not_allowed"
    COMPONENT_DENIED = "component_denied"
    DECISION_REQUIRED = "decision_required"
    DECISION_STALE = "decision_stale"
    DECISION_INVALID_CHOICE = "decision_invalid_choice"
    LICENSE_TEXT_MISSING = "license_text_missing"
    ATTRIBUTION_MISSING = "attribution_missing"


class Component(BaseModel):
    """One third-party library, as read from the SBOM."""

    name: str
    version: str = ""
    purl: str = ""
    license_expression: str = ""
    """SPDX expression exactly as declared in the SBOM (may be empty)."""
    copyright: str = ""
    homepage: str = ""

    @property
    def key(self) -> str:
        """Stable identifier used in policies, decisions and reports."""
        return self.purl or (f"{self.name}@{self.version}" if self.version else self.name)

    @property
    def display(self) -> str:
        return f"{self.name} {self.version}".strip()


class LicenseRule(BaseModel):
    """An entry of the license whitelist."""

    id: str
    """SPDX license id, e.g. ``Apache-2.0``."""
    requires_notice: bool = True
    requires_license_text: bool = True
    note: str = ""


class ComponentRule(BaseModel):
    """An entry of the component whitelist / denylist.

    ``match`` is either a purl, a ``name@version`` string or a name. A trailing
    ``*`` makes it a prefix match, so ``pkg:npm/@acme/*`` covers a whole scope.
    """

    match: str
    note: str = ""

    def matches(self, component: Component) -> bool:
        candidates = [component.purl, component.key, component.name]
        if self.match.endswith("*"):
            prefix = self.match[:-1]
            return any(c.startswith(prefix) for c in candidates if c)
        return any(c == self.match for c in candidates if c)


class Policy(BaseModel):
    """The rules a project applies to its dependencies.

    Copyleft is not special-cased anywhere in the code: a project that may ship
    copyleft simply lists those licenses in ``allowed_licenses``.
    """

    name: str = "default"
    version: str = "1"
    allowed_licenses: list[LicenseRule] = Field(default_factory=list)
    denied_licenses: list[str] = Field(default_factory=list)
    """Always an error, even when listed as allowed (explicit veto)."""
    unknown_license_severity: Severity = Severity.ERROR
    """How to treat components whose license is missing or not in the whitelist."""
    allowed_components: list[ComponentRule] = Field(default_factory=list)
    """Exceptions: these components pass even if their license does not."""
    denied_components: list[ComponentRule] = Field(default_factory=list)
    require_license_texts: bool = True
    require_attributions: bool = False

    def license_rule(self, license_id: str) -> LicenseRule | None:
        for rule in self.allowed_licenses:
            if rule.id.lower() == license_id.lower():
                return rule
        return None

    def is_denied_license(self, license_id: str) -> bool:
        return any(denied.lower() == license_id.lower() for denied in self.denied_licenses)


class Decision(BaseModel):
    """A documented choice for a multi-licensed component.

    The tool never picks a license on its own — an ``OR`` expression is only
    compliant once a decision exists, and the decision is part of the shipped
    package.
    """

    component: str
    """purl, ``name@version``, name, or a ``*``-suffixed prefix."""
    expression: str = ""
    """Expression the decision was made for; used to detect upstream changes."""
    chosen: str
    rationale: str = ""
    decided_by: str = ""
    decided_at: date | None = None

    def matches(self, component: Component) -> bool:
        return ComponentRule(match=self.component).matches(component)


class ResolvedComponent(BaseModel):
    """A component after license normalization and decision resolution."""

    component: Component
    normalized_expression: str = ""
    """SPDX expression after alias mapping, e.g. ``MIT OR Apache-2.0``."""
    effective_licenses: list[str] = Field(default_factory=list)
    """Licenses that actually apply after the decision has been taken.

    ``AND`` expressions keep every license, ``OR`` expressions keep the chosen one.
    """
    decision: Decision | None = None
    needs_decision: bool = False


class Finding(BaseModel):
    code: FindingCode
    severity: Severity
    component: str = ""
    message: str
    hint: str = ""


class ComplianceReport(BaseModel):
    """Machine readable result — the evidence of the compliance check."""

    policy_name: str
    policy_version: str
    tool_version: str
    generated_at: str
    sbom_sha256: str
    components: list[ResolvedComponent]
    findings: list[Finding]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    @property
    def passed(self) -> bool:
        return not self.errors
