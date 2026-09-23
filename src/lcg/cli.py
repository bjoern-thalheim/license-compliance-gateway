"""Command line interface.

``lcg check``  -> policy gate only (fast, for pull requests)
``lcg build``  -> full compliance package (for releases)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from lcg.config import ConfigError, load_decisions, load_policy
from lcg.evaluate import evaluate
from lcg.models import ComplianceReport, Severity
from lcg.pack import PackInputs, build_package
from lcg.resolve import resolve
from lcg.sbom import SbomError, components_of, load_sbom
from lcg.version import __version__

app = typer.Typer(
    add_completion=False,
    help="Erzeugt ein auslieferbares Compliance-Paket aus einer CycloneDX-SBOM.",
)

SbomOption = Annotated[Path, typer.Option("--sbom", "-s", help="CycloneDX-SBOM (JSON).")]
PolicyOption = Annotated[Path, typer.Option("--policy", "-p", help="Policy-Datei (YAML).")]
DecisionsOption = Annotated[
    Path | None,
    typer.Option("--decisions", "-d", help="Entscheidungsdatei oder -verzeichnis."),
]
StrictOption = Annotated[
    bool, typer.Option("--strict/--no-strict", help="Warnungen wie Fehler behandeln.")
]


@app.command()
def check(
    sbom: SbomOption,
    policy: PolicyOption,
    decisions: DecisionsOption = None,
    strict: StrictOption = False,
) -> None:
    """Prüft die SBOM gegen die Policy. Exit-Code 1 bei Verstößen."""
    report = _run_check(sbom, policy, decisions)
    _print_findings(report)
    raise typer.Exit(_exit_code(report, strict))


@app.command()
def build(
    sbom: SbomOption,
    policy: PolicyOption,
    output: Annotated[Path, typer.Option("--output", "-o", help="Zielverzeichnis.")] = Path(
        "dist/compliance"
    ),
    decisions: DecisionsOption = None,
    license_texts: Annotated[
        Path | None, typer.Option("--license-texts", help="Verzeichnis mit Lizenztexten.")
    ] = None,
    notices: Annotated[
        Path | None, typer.Option("--notices", help="Verzeichnis mit Attributionen.")
    ] = None,
    strict: StrictOption = False,
    fail_on_error: Annotated[
        bool,
        typer.Option(
            "--fail-on-error/--no-fail-on-error",
            help="Exit-Code 1, wenn die Prüfung fehlschlägt (Paket wird trotzdem erzeugt).",
        ),
    ] = True,
) -> None:
    """Erzeugt das vollständige Compliance-Paket."""
    inputs = PackInputs(
        sbom=sbom,
        policy=policy,
        decisions=decisions,
        license_texts=license_texts,
        notices=notices,
    )
    try:
        result = build_package(inputs, output)
    except (SbomError, ConfigError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc

    _print_findings(result.report)
    typer.echo(f"\nPaket geschrieben nach {result.output_dir} ({len(result.files)} Dateien)")
    code = _exit_code(result.report, strict)
    raise typer.Exit(code if fail_on_error else 0)


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind-Adresse.")] = "0.0.0.0",  # noqa: S104
    port: Annotated[int, typer.Option(help="Port.")] = 8000,
) -> None:
    """Startet den zustandslosen HTTP-Service."""
    import uvicorn

    uvicorn.run("lcg.api:app", host=host, port=port)


@app.command()
def version() -> None:
    """Zeigt die Tool-Version."""
    typer.echo(__version__)


def _run_check(sbom: Path, policy: Path, decisions: Path | None) -> ComplianceReport:
    try:
        document, digest = load_sbom(sbom)
        loaded_policy = load_policy(policy)
        loaded_decisions = load_decisions(decisions)
    except (SbomError, ConfigError) as exc:
        typer.secho(str(exc), fg=typer.colors.RED, err=True)
        raise typer.Exit(2) from exc
    resolved = resolve(components_of(document), loaded_decisions)
    return evaluate(resolved, loaded_policy, sbom_sha256=digest)


def _print_findings(report: ComplianceReport) -> None:
    colors = {
        Severity.ERROR: typer.colors.RED,
        Severity.WARNING: typer.colors.YELLOW,
        Severity.INFO: typer.colors.BLUE,
    }
    for finding in report.findings:
        typer.secho(
            f"[{finding.severity}] {finding.code}: {finding.message}",
            fg=colors[finding.severity],
            err=not report.passed,
        )
    summary = (
        f"{len(report.components)} Komponenten, "
        f"{len(report.errors)} Fehler, {len(report.warnings)} Warnungen"
    )
    typer.secho(summary, fg=typer.colors.GREEN if report.passed else typer.colors.RED)


def _exit_code(report: ComplianceReport, strict: bool) -> int:
    if report.errors or (strict and report.warnings):
        return 1
    return 0


def main() -> None:  # pragma: no cover - console entry point
    sys.exit(app())
