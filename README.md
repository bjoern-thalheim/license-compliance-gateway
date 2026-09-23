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

## Lokal ausprobieren

### 0. Voraussetzungen

Nur [uv](https://docs.astral.sh/uv/) (Python 3.12 holt uv selbst):

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
cd license-compliance-gateway
uv sync --all-groups          # legt .venv an und installiert alles inkl. Testtools
uv run lcg --help
```

### 1. Prüfung, die fehlschlägt

Die Beispiel-SBOM enthält bewusst eine Dual-Lizenz-Komponente:

```bash
uv run lcg check -s examples/sbom.cdx.json -p examples/policy.yaml
```

```
4 Komponenten, 1 Fehler, 0 Warnungen
[error] decision_required: dual-licensed-lib 2.1.0 is multi-licensed (MIT OR Apache-2.0)
        and needs a documented decision.
```

`echo $?` zeigt `1` – genau das lässt einen CI-Job rot werden.

### 2. Prüfung, die durchläuft

Mit dem Entscheidungsverzeichnis (`examples/decisions/requests.yaml` wählt MIT):

```bash
uv run lcg check -s examples/sbom.cdx.json -p examples/policy.yaml -d examples/decisions
# 4 Komponenten, 0 Fehler, 0 Warnungen   -> Exit 0
```

### 3. Paket bauen und anschauen

```bash
uv run lcg build \
  -s examples/sbom.cdx.json \
  -p examples/policy.yaml \
  -d examples/decisions \
  --license-texts examples/license-texts \
  -o dist/compliance

ls -R dist/compliance
xdg-open dist/compliance/compliance-report.html   # oder im Browser öffnen
```

Die Warnung `attribution_missing` für `legacy-lib` ist Absicht: Die Komponente
hat kein `copyright` in der SBOM. Mit `--strict` würde sie zum Fehler.

### 4. Selbst experimentieren

Jede dieser Änderungen sollte ein anderes Ergebnis erzeugen – ein guter Weg,
die Regeln zu verstehen:

| Änderung | Erwartetes Ergebnis |
| --- | --- |
| In `examples/policy.yaml` `MIT` aus `allowed_licenses` entfernen | `license_not_allowed` |
| In `examples/decisions/requests.yaml` `chosen: GPL-3.0-only` setzen | `decision_invalid_choice` |
| Dort `expression: "MIT OR BSD-3-Clause"` setzen | `decision_stale` (SBOM sagt etwas anderes) |
| `--license-texts` weglassen | `license_text_missing` je Lizenz |
| In der SBOM eine Lizenz auf `"Foo License"` ändern | `license_unparseable` |
| `unknown_license_severity: warning` setzen | dieselben Fälle nur noch als Warnung |

### 5. Mit einer echten SBOM

[syft](https://github.com/anchore/syft) erzeugt die SBOM aus einem beliebigen
Projektverzeichnis – hier das Tool auf sich selbst angewendet:

```bash
syft dir:. -o cyclonedx-json > sbom.cdx.json
uv run lcg check -s sbom.cdx.json -p examples/policy.yaml -d examples/decisions
```

Erwartungsgemäß meldet das viele Findings: Die Beispiel-Policy ist streng und
kennt die echten Abhängigkeiten nicht. Genau dieser Lauf steht als Job
`compliance-package` in der CI und lädt das Paket als Artefakt hoch.

Exit-Codes: `0` = bestanden, `1` = Policy-Verstoß (CI-Gate), `2` = fehlerhafte
Eingabe. Mit `--strict` zählen auch Warnungen als Verstoß.

### 6. Tests

```bash
uv run pytest -q          # 26 Tests, decken die Fälle aus Schritt 4 ab
uv run pytest -q -k decision
```

Die Tests sind zugleich die kompakteste Dokumentation der Regeln:
`tests/test_pipeline.py` enthält pro Finding-Typ einen Fall.

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
# {"status":"ok","version":"0.1.0"}
```

| Endpoint | Zweck |
| --- | --- |
| `GET /healthz` | Liveness/Readiness |
| `POST /v1/check` | SBOM + Policy + Entscheidungen -> JSON-Report |
| `POST /v1/package` | dasselbe -> ZIP mit dem kompletten Paket (`X-Compliance-Result`-Header) |

Der Service hält keinen Zustand: jede Anfrage wird in einem temporären
Verzeichnis gebaut, das danach verworfen wird. Interaktiv erkunden lässt er
sich über die generierte OpenAPI-Oberfläche unter <http://localhost:8000/docs>.

Der Request-Body enthält alle Eingaben als JSON (`sbom`, `policy`,
`decisions`). Aus den Beispieldateien gebaut:

```bash
uv run python - <<'PY' > request.json
import json, pathlib, yaml
print(json.dumps({
    "sbom": json.loads(pathlib.Path("examples/sbom.cdx.json").read_text()),
    "policy": yaml.safe_load(pathlib.Path("examples/policy.yaml").read_text()),
    "decisions": [yaml.safe_load(p.read_text())
                  for p in pathlib.Path("examples/decisions").glob("*.yaml")],
}, default=str))
PY

curl -s -X POST localhost:8000/v1/check -H 'Content-Type: application/json' -d @request.json
curl -s -X POST localhost:8000/v1/package -H 'Content-Type: application/json' \
     -d @request.json -o compliance-package.zip
unzip -l compliance-package.zip
```

Hinweis: Über HTTP lassen sich derzeit keine Lizenztexte mitgeben. Bei
`require_license_texts: true` meldet der Service deshalb `license_text_missing`,
während dieselbe Eingabe per CLI mit `--license-texts` besteht.

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

## Code verstehen

Jedes Modul ist ein Schritt der Pipeline und hat genau eine Aufgabe – in dieser
Reihenfolge gelesen ergibt sich der komplette Ablauf:

| Datei | Aufgabe | Einstieg |
| --- | --- | --- |
| `src/lcg/models.py` | Alle Datenstrukturen (Pydantic): `Component`, `Policy`, `Decision`, `Finding`, `ComplianceReport` | zuerst lesen – der Rest arbeitet nur auf diesen Typen |
| `src/lcg/sbom.py` | CycloneDX-JSON -> `Component`; vereinheitlicht `expression`, SPDX-IDs und Lizenznamen | `components_of()` |
| `src/lcg/licenses.py` | SPDX-Ausdrücke normalisieren; Aliase wie `Apache 2.0` -> `Apache-2.0`; `AND`/`OR` unterscheiden | `normalize()`, `is_choice()` |
| `src/lcg/resolve.py` | Entscheidungen zuordnen (purl > name@version > name > prefix) und effektive Lizenzen bestimmen | `resolve()` |
| `src/lcg/evaluate.py` | Policy anwenden, Findings erzeugen – hier stehen alle Regeln | `evaluate()` |
| `src/lcg/collect.py` | Lizenztexte und Attributionen im Dateisystem suchen (kein Netzwerk) | `find_license_text()` |
| `src/lcg/pack.py` | Paket schreiben: SBOMs, Notices, Reports, `manifest.json` mit SHA-256 | `build_package()` |
| `src/lcg/templates/` | Jinja2-Vorlagen für `THIRD-PARTY-NOTICES.md`, `decisions.md`, HTML-Report | – |
| `src/lcg/cli.py` | `lcg check/build/serve/version`, Exit-Codes | `check()`, `build()` |
| `src/lcg/api.py` | FastAPI-Wrapper um dieselbe Pipeline, ohne Zustand | `/v1/check`, `/v1/package` |
| `src/lcg/config.py` | Policy- und Entscheidungsdateien laden und validieren | `load_policy()` |

Zwei Stellen lohnen besondere Aufmerksamkeit:

- `resolve.py` entscheidet **nie selbst** bei `OR`, sondern markiert die
  Komponente mit `needs_decision`.
- `evaluate.py` ist die einzige Stelle mit Policy-Logik; Denylist schlägt
  Allowlist, und eine Komponenten-Ausnahme überspringt die Lizenzprüfung.

## Entwicklung

```bash
uv run pytest
uv run ruff check .
uv run ruff format .
uv run mypy
```

## Stand

PoC: Fokus auf CycloneDX-JSON. Nicht enthalten (bewusst): SPDX-Input, Abruf von
Lizenztexten aus dem Netz, Signatur des Pakets (cosign/Sigstore). Der
Apache-2.0-Text unter `examples/license-texts/` ist nur Beispielmaterial.
