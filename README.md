# license-compliance-gateway

Erzeugt aus einer **CycloneDX-SBOM** und ergänzenden Policy-Dateien ein
**auslieferbares Compliance-Paket** – für CRA/SBOM-Anforderungen ebenso wie für
den Nachweis lizenzkonformer Nutzung von Fremdbibliotheken.

Nutzbar als CLI (CI-Gate) und als zustandsloser HTTP-Service (Container, k8s).

## Pipeline

```
SBOM (CycloneDX JSON)
  + policy.yaml         Whitelist erlaubter Lizenzen/Bibliotheken, Denylist, Schweregrade
  + decisions/*.yaml    Entscheidungen für Multi-/Dual-Lizenz-Bibliotheken
  + license-texts/      Lizenztexte (<SPDX-ID>.txt oder <komponente>.txt)
  + notices/            Attributionen, wenn nicht in der SBOM enthalten
        |
        v
  1. Parsen        CycloneDX -> Komponentenmodell
  2. Normalisieren Lizenz-Aliase -> SPDX-Expression
  3. Auflösen      AND: alle Lizenzen gelten; OR: nur mit dokumentierter Entscheidung
  4. Prüfen        Policy anwenden -> Findings (error/warning/info)
  5. Sammeln       Lizenztexte + Attributionen (offline, reproduzierbar)
  6. Paketieren    dist/compliance/
```

### Ergebnis

| Datei | Inhalt |
| --- | --- |
| `sbom.cdx.json` | unveränderte Quell-SBOM |
| `sbom.enriched.cdx.json` | SBOM mit effektiven Lizenzen und Entscheidungs-Referenzen |
| `THIRD-PARTY-NOTICES.md` | Attributionen |
| `licenses/<SPDX-ID>.txt` | erforderliche Lizenztexte |
| `decisions.md` | dokumentierte Multi-Lizenz-Entscheidungen |
| `compliance-report.json` | maschinenlesbarer Nachweis (Findings, Policy, Versionen) |
| `compliance-report.html` | menschenlesbarer Nachweis |
| `manifest.json` | SHA-256 aller Dateien, SBOM-Hash, Tool-/Policy-Version, Ergebnis |

## Schnellstart

```bash
uv sync --all-groups

# Prüfung (schlägt fehl: Dual-Lizenz ohne Entscheidung)
uv run lcg check -s examples/sbom.cdx.json -p examples/policy.yaml

# Prüfung mit Entscheidungen
uv run lcg check -s examples/sbom.cdx.json -p examples/policy.yaml -d examples/decisions

# Vollständiges Paket
uv run lcg build \
  -s examples/sbom.cdx.json \
  -p examples/policy.yaml \
  -d examples/decisions \
  --license-texts examples/license-texts \
  -o dist/compliance
```

Exit-Code `0` = bestanden, `1` = Policy-Verstoß (CI-Gate), `2` = fehlerhafte Eingabe.
Mit `--strict` zählen auch Warnungen als Verstoß.

SBOM erzeugen z. B. mit [syft](https://github.com/anchore/syft):

```bash
syft dir:. -o cyclonedx-json > sbom.cdx.json
```

## Policy

```yaml
name: example-proprietary
version: "1"
allowed_licenses:
  - id: MIT
  - id: Apache-2.0
  - id: CC0-1.0
    requires_notice: false
    requires_license_text: false
denied_licenses: [AGPL-3.0-only]      # Veto, auch wenn sonst erlaubt
unknown_license_severity: error       # unbekannte/nicht gelistete Lizenz
allowed_components:                   # Ausnahmen (Prefix mit * möglich)
  - match: pkg:npm/@acme/*
    note: "Interner Code"
denied_components: []
require_license_texts: true
require_attributions: true
```

Copyleft ist kein Sonderfall im Code: Ein Projekt, dessen Code ohnehin offen
ist, nimmt GPL & Co. einfach in `allowed_licenses` auf.

## Entscheidungen für Mehrfachlizenzen

Das Tool wählt **nie selbst** aus `MIT OR Apache-2.0`. Eine solche Komponente
ist erst konform, wenn eine Entscheidung dokumentiert ist:

```yaml
component: "pkg:pypi/dual-licensed-lib@2.1.0"   # purl, name@version, name oder prefix*
expression: "MIT OR Apache-2.0"                  # Stand bei der Entscheidung
chosen: "MIT"
rationale: "Patentklausel nicht erforderlich."
decided_by: "bjoern"
decided_at: 2026-09-23
```

Ändert sich die Lizenz upstream, meldet das Tool die Entscheidung als veraltet
(`decision_stale`); eine Wahl außerhalb des Angebots als `decision_invalid_choice`.

## HTTP-Service

```bash
uv run lcg serve --port 8000
curl -s localhost:8000/healthz
```

| Endpoint | Zweck |
| --- | --- |
| `GET /healthz` | Liveness/Readiness |
| `POST /v1/check` | SBOM + Policy + Entscheidungen -> JSON-Report |
| `POST /v1/package` | dasselbe -> ZIP mit dem kompletten Paket (`X-Compliance-Result`-Header) |

Der Service hält keinen Zustand: jede Anfrage wird in einem temporären
Verzeichnis gebaut, das danach verworfen wird.

### Container / Kubernetes

```bash
docker build -t license-compliance-gateway:0.1.0 .
docker run --rm -p 8000:8000 license-compliance-gateway:0.1.0
kubectl apply -f deploy/k8s/
```

Dasselbe Image dient als CI-Gate:

```bash
docker run --rm -v "$PWD:/work" -w /work license-compliance-gateway:0.1.0 \
  lcg check -s sbom.cdx.json -p policy.yaml -d decisions
```

## Entwicklung

```bash
uv run pytest
uv run ruff check .
uv run mypy
```

## Stand

PoC: Fokus auf CycloneDX-JSON. Nicht enthalten (bewusst): SPDX-Input, Abruf von
Lizenztexten aus dem Netz, Signatur des Pakets (cosign/Sigstore). Der
Apache-2.0-Text unter `examples/license-texts/` ist nur Beispielmaterial.
