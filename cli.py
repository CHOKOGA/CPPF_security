"""
Interface en ligne de commande (CLI) professionnelle pour DevSecAssist.
Supporte les sorties HTML, JSON, SARIF, la déduplication et les codes de sortie CI/CD.
"""
import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table

from utils.target_detector import TargetDetector
from utils.risk_calculator import RiskCalculator
from analyzers.secret_scanner import SecretScanner
from analyzers.sast_linter import SASTLinter
from analyzers.header_auditor import HeaderAuditor
from analyzers.config_auditor import ConfigAuditor
from analyzers.dependency_auditor import DependencyAuditor
from reporting.html_reporter import HTMLReporter
from reporting.json_reporter import JSONReporter, SARIFReporter

console = Console()

def main():
    parser = argparse.ArgumentParser(description="DevSecAssist - Assistant de Sécurité Local pour Développeurs")
    parser.add_argument("--path", "-p", default=".", help="Chemin du projet local à analyser")
    parser.add_argument("--url", "-u", default=None, help="URL locale de l'application en cours d'exécution (ex: http://localhost:8000)")
    parser.add_argument("--output", "-o", default="report.html", help="Nom du fichier de rapport généré")
    parser.add_argument("--format", "-f", choices=["html", "json", "sarif"], default="html", help="Format de sortie du rapport (html, json, sarif)")
    parser.add_argument("--fail-on-high", action="store_true", help="Retourne un code d'erreur non-nul (exit 1) si des alerte de haute sévérité sont trouvées (pour CI/CD)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Mode silencieux (masque l'affichage console)")

    args = parser.parse_args()

    if not args.quiet:
        console.print("\n[bold cyan]🛡️  Lancement de DevSecAssist v0.2.0 - Audit de Sécurité Local[/bold cyan]\n")

    project_path = Path(args.path).resolve()
    raw_findings = []

    # 1. Détection du type de projet
    if not args.quiet:
        console.print(f"[bold]🔍 Analyse du répertoire :[/bold] [yellow]{project_path}[/yellow]")
    project_info = TargetDetector.detect_project_type(project_path)
    if project_info["stacks"] and not args.quiet:
        console.print(f"   ► Stacks détectées : [green]{', '.join(project_info['stacks'])}[/green]")

    # 2. Scans
    if not args.quiet:
        console.print("   ► Analyse des secrets exposés...")
    raw_findings.extend(SecretScanner.scan_directory(project_path))

    if not args.quiet:
        console.print("   ► Analyse statique du code (SAST)...")
    raw_findings.extend(SASTLinter.analyze_directory(project_path))

    if not args.quiet:
        console.print("   ► Audit des fichiers de configuration...")
    raw_findings.extend(ConfigAuditor.audit_project(project_path))

    if not args.quiet:
        console.print("   ► Audit des manifests de dépendances...")
    raw_findings.extend(DependencyAuditor.audit_dependencies(project_path))

    if args.url:
        if not args.quiet:
            console.print(f"   ► Audit passif sur [yellow]{args.url}[/yellow]...")
        raw_findings.extend(HeaderAuditor.audit_target(args.url))

    # 3. Déduplication et Calcul du Score de Risque
    findings = RiskCalculator.deduplicate_findings(raw_findings)
    score, grade, stats = RiskCalculator.calculate_score(findings)

    # 4. Affichage console
    if not args.quiet:
        console.print(f"\n[bold]📈 Score de Sécurité Global :[/bold] [bold cyan]{score}/100[/bold cyan] (Note : [bold green]{grade}[/bold green])")
        console.print("\n[bold]📊 Résumé des Découvertes Dédupliquées :[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Type / Catégorie")
        table.add_column("Sévérité")
        table.add_column("Source")
        table.add_column("Conseil")

        for finding in findings:
            sev = finding.get("severity", "INFO")
            sev_color = "red" if sev == "HAUTE" else ("yellow" if sev == "MOYENNE" else "blue")
            src = finding.get("file") or finding.get("target", "-")
            table.add_row(
                finding.get("type", ""),
                f"[{sev_color}]{sev}[/{sev_color}]",
                src,
                finding.get("recommendation", "")[:70] + "..."
            )

        console.print(table)

    # 5. Génération du Rapport selon le format
    output_path = Path(args.output).resolve()
    target_name = str(project_path if not args.url else args.url)

    if args.format == "html":
        HTMLReporter.generate_report(target_name, score, grade, stats, findings, output_path)
    elif args.format == "json":
        JSONReporter.generate_report(target_name, score, grade, stats, findings, output_path)
    elif args.format == "sarif":
        SARIFReporter.generate_report(findings, output_path)

    if not args.quiet:
        console.print(f"\n[bold green]✅ Rapport [{args.format.upper()}] généré avec succès :[/bold green] [underline]{output_path}[/underline]\n")

    # 6. Gestion du code de sortie pour CI/CD
    if args.fail_on_high and stats["high"] > 0:
        if not args.quiet:
            console.print(f"[bold red]❌ Échec du build CI/CD : {stats['high']} alerte(s) de Haute Sévérité détectée(s).[/bold red]")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
