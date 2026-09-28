# Den Code verstehen

Diese Datei erklärt, wie der Code aufgebaut ist und was beim Aufruf von
`lcg check` konkret passiert. Die [README](README.md) beschreibt die Benutzung,
hier geht es um das Innenleben.

## Warum es kein `check.py` gibt

`check` ist kein eigener Baustein, sondern ein **Weg durch die Pipeline**.
Dieselben Schritte laufen bei `lcg check`, bei `lcg build` und im HTTP-Service –
sie unterscheiden sich nur darin, wo die Eingaben herkommen und was am Ende
ausgegeben wird. Die Module sind deshalb nach *Verarbeitungsschritt* geschnitten,
nicht nach Befehl:

```
Eingabe               Schritt (Modul)                 Ergebnis-Typ
---------------------------------------------------------------------------
sbom.cdx.json    ->   sbom.py       Parsen        ->  list[Component]
                 ->   licenses.py   Normalisieren ->  "MIT OR Apache-2.0"
decisions/*.yaml ->   resolve.py    Auflösen      ->  list[ResolvedComponent]
policy.yaml      ->   evaluate.py   Prüfen        ->  ComplianceReport
license-texts/   ->   collect.py    Sammeln       ->  Texte, Attributionen
                 ->   pack.py       Paketieren    ->  dist/compliance/
```

`cli.py` und `api.py` sind nur zwei Fassaden davor:

| | liest Eingaben | schreibt Ausgaben | Code |
| --- | --- | --- | --- |
| `lcg check` | Dateien | Terminal + Exit-Code | `cli.check` |
| `lcg build` | Dateien | Verzeichnis | `cli.build` → `pack.build_package` |
| `POST /v1/check` | JSON-Body | JSON-Report | `api.check` |
| `POST /v1/package` | JSON-Body | ZIP | `api.package` → `pack.build_package_from_data` |

## Der Weg einer SBOM durch `lcg check`

Einstieg: `check()` in `src/lcg/cli.py`. Der eigentliche Ablauf steht in
`_run_check()` – fünf Zeilen, die der Reihe nach die Module aufrufen:

```python
document, digest = load_sbom(sbom)  # sbom.py
loaded_policy = load_policy(policy)  # config.py
loaded_decisions = load_decisions(decisions)  # config.py
resolved = resolve(components_of(document), loaded_decisions)  # resolve.py
return evaluate(resolved, loaded_policy, sbom_sha256=digest)  # evaluate.py
```

Danach druckt `_print_findings()` die Findings und `_exit_code()` bestimmt den
Exit-Code (`1`, sobald ein Fehler existiert – mit `--strict` auch bei Warnungen).

### Schritt 1 – `sbom.py`: CycloneDX lesen

`load_sbom()` liest die Datei, bildet den SHA-256 **der Originaldatei** (der
später im Manifest als Nachweis steht) und prüft `bomFormat == "CycloneDX"`.

`components_of()` läuft rekursiv durch `components` (CycloneDX erlaubt
verschachtelte Komponenten) und erzeugt je Eintrag ein `Component`.

Die eigentliche Arbeit steckt in `_license_expression()`: CycloneDX kennt für
Lizenzen mehrere Schreibweisen, die hier auf **eine** Zeichenkette reduziert
werden.

```jsonc
"licenses": [{"expression": "MIT OR Apache-2.0"}]          // -> "MIT OR Apache-2.0"
"licenses": [{"license": {"id": "MIT"}}]                   // -> "MIT"
"licenses": [{"license": {"id": "MIT"}},
             {"license": {"id": "BSD-3-Clause"}}]          // -> "MIT AND BSD-3-Clause"
```

Die letzte Zeile ist eine inhaltliche Entscheidung: Mehrere einzeln gelistete
Lizenzen gelten **alle**, also `AND`. Eine Wahlmöglichkeit kann CycloneDX nur
als `expression` ausdrücken.

### Schritt 2 – `licenses.py`: SPDX normalisieren

Alles, was mit Lizenzausdrücken zu tun hat, liegt hier; der Rest des Codes
arbeitet nur mit dem Ergebnis.

- `normalize("Apache 2.0")` → `"Apache-2.0"` (über die `ALIASES`-Tabelle) und
  parst danach mit der Bibliothek `license-expression`. Unverständliches
  ergibt `LicenseExpressionError`.
- `is_choice("MIT OR Apache-2.0")` → `True`. Das ist die Weiche für Schritt 3.
- `license_ids("MIT OR Apache-2.0")` → `["MIT", "Apache-2.0"]`.

Die `ALIASES`-Tabelle ist der Ort für Erweiterungen, wenn eine reale SBOM eine
kreative Schreibweise liefert.

### Schritt 3 – `resolve.py`: effektive Lizenzen bestimmen

`resolve_one()` entscheidet für jede Komponente zwischen drei Fällen:

| Ausdruck | `effective_licenses` | `needs_decision` |
| --- | --- | --- |
| `MIT` | `["MIT"]` | `False` |
| `MIT AND BSD-3-Clause` | `["MIT", "BSD-3-Clause"]` | `False` |
| `MIT OR Apache-2.0` ohne Entscheidung | `[]` | `True` |
| `MIT OR Apache-2.0` mit Entscheidung `MIT` | `["MIT"]` | `False` |

**Das Tool wählt nie selbst.** Bei `OR` wird nur markiert, dass eine
Entscheidung fehlt; den Fehler daraus macht erst `evaluate.py`.

Passt mehr als eine Entscheidung auf eine Komponente, gewinnt die
spezifischste – `_specificity()` bewertet exakte purl (10000) vor
`name@version` (9000) vor Name (1000) vor Präfix (`*`, nach Länge).

### Schritt 4 – `evaluate.py`: die Policy anwenden

Das ist die einzige Stelle mit Regelwerk. `_check_component()` gibt die
Reihenfolge vor, und die Reihenfolge ist die Regel:

```text
1. denied_components   -> sofort Fehler, Rest wird nicht mehr geprüft
2. allowed_components  -> Ausnahme: Komponente ist fertig, keine Lizenzprüfung
3. _check_expression        -> license_missing / license_unparseable
4. _check_decision          -> decision_required / _stale / _invalid_choice
5. _check_effective_licenses-> license_denied / license_not_allowed
```

Drei Punkte, die man leicht übersieht:

- **Denylist schlägt Allowlist** (Schritt 1 und 5): `denied_licenses` ist ein
  Veto, auch wenn dieselbe Lizenz in `allowed_licenses` steht.
- Eine **Komponenten-Ausnahme überspringt die Lizenzprüfung vollständig** –
  das ist der Hebel für internen Code, der keine SPDX-Lizenz hat.
- `unknown_license_severity` steuert nur die *unklaren* Fälle (fehlende, nicht
  parsebare, nicht gelistete Lizenz). Fehlende Entscheidungen und Denylist-
  Treffer sind immer Fehler.

`decision_stale` entsteht in `_differs()`: Die Entscheidung hält die Expression
fest, für die sie getroffen wurde. Ändert der Upstream seine Lizenz, passt der
gespeicherte Ausdruck nicht mehr zum normalisierten aktuellen – und die
Entscheidung muss erneut getroffen werden.

Ergebnis ist ein `ComplianceReport`; `report.passed` ist schlicht
„keine Findings mit Severity `error`".

### Schritt 5 – `collect.py`: Texte und Attributionen suchen

Nur Dateisystem, **kein Netzwerk** – damit ein Build reproduzierbar ist und in
einer abgeschotteten CI oder im Container läuft. Lizenztext: erst
`<key>.txt` (komponentenspezifisch), dann `<SPDX-ID>.txt`. Attribution: erst
das `copyright`-Feld der SBOM, dann `<notices>/<key>.txt`.

### Schritt 6 – `pack.py`: das Paket schreiben

`build_package()` ruft dieselben Schritte 1–5 auf und schreibt danach die
Dateien. Zwei Dinge passieren hier zusätzlich:

- `_gather_license_texts()` / `_gather_attributions()` **hängen weitere
  Findings an den Report an** (`license_text_missing`, `attribution_missing`).
  Diese beiden Findings kann `lcg check` gar nicht melden, weil es keine
  Textverzeichnisse liest – deshalb ist `build` die strengere Prüfung.
- `_enrich()` kopiert die SBOM und ergänzt je Komponente CycloneDX-`properties`:

  ```json
  {"name": "lcg:effective-licenses", "value": "MIT"}
  {"name": "lcg:decision",           "value": "MIT"}
  ```

  Die Originaldatei bleibt daneben unverändert erhalten – wichtig, weil ihr
  Hash der Bezugspunkt im Manifest ist.

`_manifest()` erzeugt zum Schluss den Nachweis: SHA-256 jeder geschriebenen
Datei, Hash der Quell-SBOM, Policy- und Tool-Version, Ergebnis und Zählerstände.

## Die Datenstrukturen (`models.py`)

Wer nur eine Datei lesen will, sollte diese lesen: Alle Module tauschen
ausschließlich diese Typen aus, und jeder ist ein Pydantic-Modell, also
zugleich Validierung und JSON-Schema.

```
Component          eine Bibliothek aus der SBOM (name, version, purl, expression, copyright)
  .key             stabiler Bezeichner: purl, sonst name@version  -> in Policy, Decisions, Report
Policy             allowed/denied_licenses, allowed/denied_components, Schweregrade
Decision           component, expression, chosen, rationale, decided_by, decided_at
ResolvedComponent  Component + normalized_expression + effective_licenses + decision/needs_decision
Finding            code, severity, component, message, hint
ComplianceReport   Metadaten + alle ResolvedComponents + alle Findings (.passed, .errors, .warnings)
```

`FindingCode` ist die vollständige Liste dessen, was schiefgehen kann – ein
guter Startpunkt, um von einer Meldung zum verantwortlichen Code zu springen:
Jeder Code wird an genau einer Stelle erzeugt, also führt
`grep -rn LICENSE_DENIED src/lcg --include='*.py'` direkt zur zuständigen Regel.

## Wo fange ich an, wenn ich …

| Ziel | Datei | Funktion |
| --- | --- | --- |
| eine weitere Lizenz-Schreibweise unterstützen | `licenses.py` | `ALIASES` |
| eine neue Policy-Regel einführen | `models.py` + `evaluate.py` | `Policy`, `_check_component` |
| ein Feld aus der SBOM zusätzlich lesen | `sbom.py` + `models.py` | `_to_component`, `Component` |
| eine Datei zum Paket hinzufügen | `pack.py` (+ `templates/`) | `_build` |
| das Aussehen des HTML-Reports ändern | `templates/report.html.j2` | – |
| einen Endpoint ergänzen | `api.py` | – |
| verstehen, wann welches Finding kommt | `tests/test_pipeline.py` | ein Test pro Fall |

## Tests als Dokumentation

`tests/test_pipeline.py` enthält zu den meisten Findings einen minimalen Fall
(z. B. `test_stale_decision_is_detected`, `test_denied_license_beats_whitelist`,
`test_component_allowance_skips_license_checks`); die Fixtures in
`tests/conftest.py` laden die Dateien aus `examples/`. Wer eine Regel verstehen
will, liest am schnellsten den zugehörigen Test:

```bash
uv run pytest -k decision -v
```
