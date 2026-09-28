"""Step 3 of the pipeline: one effective license set per component.

An ``AND`` expression keeps every license. An ``OR`` expression is a choice the
tool refuses to make on its own — it needs a :class:`~lcg.models.Decision`.
"""

from __future__ import annotations

from lcg import licenses
from lcg.models import Component, Decision, ResolvedComponent


def resolve(components: list[Component], decisions: list[Decision]) -> list[ResolvedComponent]:
    return [resolve_one(component, decisions) for component in components]


def resolve_one(component: Component, decisions: list[Decision]) -> ResolvedComponent:
    if not component.license_expression.strip():
        return ResolvedComponent(component=component)

    try:
        normalized = licenses.normalize(component.license_expression)
    except licenses.LicenseExpressionError:
        return ResolvedComponent(component=component, normalized_expression="")

    if not licenses.is_choice(normalized):
        return ResolvedComponent(
            component=component,
            normalized_expression=normalized,
            effective_licenses=licenses.conjunctive_ids(normalized),
        )

    decision = find_decision(component, decisions)
    if decision is None:
        return ResolvedComponent(
            component=component,
            normalized_expression=normalized,
            needs_decision=True,
        )
    return ResolvedComponent(
        component=component,
        normalized_expression=normalized,
        effective_licenses=licenses.license_ids(decision.chosen),
        decision=decision,
    )


def find_decision(component: Component, decisions: list[Decision]) -> Decision | None:
    """Most specific decision wins: exact purl before name before prefix."""
    matching = [decision for decision in decisions if decision.matches(component)]
    if not matching:
        return None
    return max(matching, key=lambda decision: _specificity(decision, component))


def _specificity(decision: Decision, component: Component) -> int:
    if decision.component.endswith("*"):
        return len(decision.component)
    if decision.component == component.purl:
        return 10_000
    if decision.component == component.key:
        return 9_000
    return 1_000
