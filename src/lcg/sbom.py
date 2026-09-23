"""Reading CycloneDX SBOMs (JSON, spec 1.4 - 1.6)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lcg.models import Component


class SbomError(ValueError):
    """The input is not a CycloneDX JSON document."""


def load_sbom(path: Path) -> tuple[dict[str, Any], str]:
    """Return the parsed SBOM and the SHA-256 of the file as shipped."""
    raw = path.read_bytes()
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SbomError(f"{path} is not valid JSON: {exc}") from exc
    return parse_document(document), hashlib.sha256(raw).hexdigest()


def parse_document(document: Any) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise SbomError("SBOM must be a JSON object")
    if document.get("bomFormat") != "CycloneDX":
        raise SbomError("only CycloneDX SBOMs are supported (bomFormat != 'CycloneDX')")
    return document


def components_of(document: dict[str, Any]) -> list[Component]:
    """Flatten the component tree of a CycloneDX document."""
    components: list[Component] = []
    _walk(document.get("components", []), components)
    return components


def _walk(entries: Any, sink: list[Component]) -> None:
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        sink.append(_to_component(entry))
        _walk(entry.get("components", []), sink)


def _to_component(entry: dict[str, Any]) -> Component:
    return Component(
        name=str(entry.get("name", "")),
        version=str(entry.get("version", "")),
        purl=str(entry.get("purl", "")),
        license_expression=_license_expression(entry),
        copyright=str(entry.get("copyright", "")),
        homepage=_homepage(entry),
    )


def _license_expression(entry: dict[str, Any]) -> str:
    """CycloneDX allows several shapes; reduce them to one SPDX expression.

    ``[{"expression": "MIT OR Apache-2.0"}]`` is taken as-is, while a list of
    ``{"license": {"id": ...}}`` entries is joined with ``AND`` because every
    listed license applies.
    """
    licenses = entry.get("licenses")
    if not isinstance(licenses, list):
        return ""
    ids: list[str] = []
    for item in licenses:
        if not isinstance(item, dict):
            continue
        if expression := item.get("expression"):
            return str(expression)
        license_entry = item.get("license")
        if isinstance(license_entry, dict):
            value = license_entry.get("id") or license_entry.get("name")
            if value:
                ids.append(str(value))
    if not ids:
        return ""
    if len(ids) == 1:
        return ids[0]
    return " AND ".join(f"({i})" if " " in i else i for i in ids)


def _homepage(entry: dict[str, Any]) -> str:
    references = entry.get("externalReferences")
    if not isinstance(references, list):
        return ""
    for reference in references:
        if isinstance(reference, dict) and reference.get("type") in {"website", "distribution"}:
            return str(reference.get("url", ""))
    return ""
