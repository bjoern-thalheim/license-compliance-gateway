"""Step 5 of the pipeline: collect license texts and attributions.

Everything is read from the workspace — no network access — so a build is
reproducible and can run in a locked-down CI or a stateless service.

Lookup order for a license text (first hit wins):

1. ``<texts_dir>/<component-key>.txt``  (component specific text)
2. ``<texts_dir>/<SPDX-ID>.txt``        (shared text for that license)

Attributions come from the SBOM ``copyright`` field or from
``<notices_dir>/<component-key>.txt``.
"""

from __future__ import annotations

import re
from pathlib import Path

from lcg.models import ResolvedComponent

_SAFE = re.compile(r"[^A-Za-z0-9._@-]+")


def safe_name(key: str) -> str:
    """Turn a purl or ``name@version`` into a file name."""
    return _SAFE.sub("_", key).strip("_") or "component"


def find_license_text(license_id: str, item: ResolvedComponent, texts_dir: Path | None) -> str:
    if texts_dir is None:
        return ""
    for candidate in (
        texts_dir / f"{safe_name(item.component.key)}.txt",
        texts_dir / f"{license_id}.txt",
    ):
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8")
    return ""


def find_attribution(item: ResolvedComponent, notices_dir: Path | None) -> str:
    if item.component.copyright.strip():
        return item.component.copyright.strip()
    if notices_dir is None:
        return ""
    candidate = notices_dir / f"{safe_name(item.component.key)}.txt"
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8").strip()
    return ""
