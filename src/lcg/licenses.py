"""Normalization and inspection of SPDX license expressions."""

from __future__ import annotations

from license_expression import AND, OR, ExpressionError, LicenseSymbol, get_spdx_licensing

_LICENSING = get_spdx_licensing()

#: Spellings that show up in real SBOMs but are not valid SPDX ids.
ALIASES: dict[str, str] = {
    "apache 2.0": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "bsd": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "new bsd license": "BSD-3-Clause",
    "gpl-2.0+": "GPL-2.0-or-later",
    "gpl-3.0+": "GPL-3.0-or-later",
    "gplv3": "GPL-3.0-only",
    "lgplv3": "LGPL-3.0-only",
    "mit license": "MIT",
    "the mit license": "MIT",
    "mpl2": "MPL-2.0",
    "public domain": "CC0-1.0",
}


class LicenseExpressionError(ValueError):
    """Raised when an expression cannot be understood at all."""


def normalize(expression: str) -> str:
    """Return a canonical SPDX expression for ``expression``.

    Known non-SPDX spellings are mapped via :data:`ALIASES` first, then the
    expression is parsed and printed back in canonical form.
    """
    raw = expression.strip()
    if not raw:
        return ""
    aliased = ALIASES.get(raw.lower(), raw)
    try:
        parsed = _LICENSING.parse(aliased, simple=False)
    except (ExpressionError, TypeError) as exc:  # pragma: no cover - defensive
        raise LicenseExpressionError(f"cannot parse license expression {expression!r}") from exc
    if parsed is None:
        raise LicenseExpressionError(f"cannot parse license expression {expression!r}")
    return str(parsed)


def license_ids(expression: str) -> list[str]:
    """All license ids appearing in ``expression``, in order of appearance."""
    parsed = _LICENSING.parse(normalize(expression), simple=False)
    return [str(symbol) for symbol in _LICENSING.license_symbols(parsed, unique=True)]


def is_choice(expression: str) -> bool:
    """True when the expression offers a choice (``OR``) somewhere."""
    parsed = _LICENSING.parse(normalize(expression), simple=False)
    return _contains_or(parsed)


def conjunctive_ids(expression: str) -> list[str]:
    """License ids of a pure ``AND`` expression (all of them apply)."""
    return license_ids(expression)


def _contains_or(node: object) -> bool:
    if isinstance(node, OR):
        return True
    if isinstance(node, AND):
        return any(_contains_or(arg) for arg in node.args)
    if isinstance(node, LicenseSymbol):
        return False
    args = getattr(node, "args", ())
    return any(_contains_or(arg) for arg in args)
