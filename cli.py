"""
Interface en ligne de commande (CLI) pour DevSecAssist.
Utilise argparse pour éviter les dépendances externes lourdes.
"""
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table

from utils.target_detector import TargetDetector
from analyzers.secret_scanner import SecretScanner
from analyzers.sast_linter import SASTLinter
from analyzers.header_auditor import HeaderAuditor
from analyzers.config_auditor import ConfigAuditor
from analyzers.dependency_auditor import DependencyAuditor
from reporting.html_reporter import HTMLReporter

console = Console()

def main():
    parser = argparse.ArgumentParser(description="DevSecAssist - Assistant de Sécurité Local pour Développeurs")
    parser.add_argument("--path", "-p", default=".", help="Chemin du projet local à analyser")
    parser.add_argument("--url", "-u", default=None, help="URL locale de l'application en cours d'exécution (ex: http://localhost:8000)")
    parser.add_argument("--output", "-o", default="report.html", help="Nom du fichier de rapport HTML généré")

    args = parser.parse_args()

    console.print("\n[bold cyan]🛡️  Lancement de DevSecAssist - Audit de Sécurité Local[/bold cyan]\n")

    project_path = Path(args.path).resolve()
    all_findings = []

    # 1. Détection du type de projet
    console.print(f"[bold]🔍 Analyse du répertoire :[/bold] [yellow]{project_path}[/yellow]")
    project_info = TargetDetector.detect_project_type(project_path)
    if project_info["stacks"]:
        console.print(f"   ► Stacks détectées : [green]{', '.join(project_info['stacks'])}[/green]")

    # 2. Analyse des Secrets
    console.print("   ► Analyse des secrets exposés...")
    secret_findings = SecretScanner.scan_directory(project_path)
    all_findings.extend(secret_findings)

    # 3. SAST Linter (Code source)
    console.print("   ► Analyse statique du code (SAST)...")
    sast_findings = SASTLinter.analyze_directory(project_path)
    all_findings.extend(sast_findings)

    # 4. Audit des Configurations (Docker, Android, iOS, .env)
    console.print("   ► Audit des fichiers de configuration...")
    config_findings = ConfigAuditor.audit_project(project_path)
    all_findings.extend(config_findings)

    # 5. Audit des Dépendances
    console.print("   ► Audit des manifests de dépendances...")
    dep_findings = DependencyAuditor.audit_dependencies(project_path)
    all_findings.extend(dep_findings)

    # 6. Audit HTTP si URL fournie
    if args.url:
        console.print(f"   ► Audit passif de l'application en cours d'exécution sur [yellow]{args.url}[/yellow]...")
        header_findings = HeaderAuditor.audit_target(args.url)
        all_findings.extend(header_findings)

    # Affichage du résumé dans la console
    console.print("\n[bold]📊 Résumé des Découvertes :[/bold]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Type / Catégorie")
    table.add_column("Sévérité")
    table.add_column("Source")
    table.add_column("Conseil")

    for finding in all_findings:
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

    # 7. Génération du rapport HTML
    output_path = Path(args.output).resolve()
    HTMLReporter.generate_report(str(project_path if not args.url else args.url), all_findings, output_path)
    console.print(f"\n[bold green]✅ Rapport HTML généré avec succès :[/bold green] [underline]{output_path}[/underline]\n")

if __name__ == "__main__":
    main()
