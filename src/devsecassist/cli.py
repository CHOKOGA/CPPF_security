"""
Interface en ligne de commande (CLI) standardisée pour DevSecAssist.
"""
import sys
import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table

from devsecassist.engine import ScanEngine
from devsecassist.models import Severity
from devsecassist.reporting.html_reporter import HTMLReporter
from devsecassist.reporting.json_reporter import JSONReporter, SARIFReporter

console = Console()

def main():
    parser = argparse.ArgumentParser(description="DevSecAssist - Assistant de Sécurité Local pour Développeurs")
    parser.add_argument("--path", "-p", default=".", help="Chemin du projet local à analyser")
    parser.add_argument("--url", "-u", default=None, help="URL locale de l'application en cours d'exécution (ex: http://localhost:8000)")
    parser.add_argument("--output", "-o", default="report.html", help="Nom du fichier de rapport généré")
    parser.add_argument("--format", "-f", choices=["html", "json", "sarif"], default="html", help="Format de sortie du rapport (html, json, sarif)")
    parser.add_argument("--ignore-file", default=".devsecignore", help="Nom du fichier de règles d'ignoration (défaut: .devsecignore)")
    parser.add_argument("--fail-on-high", action="store_true", help="Retourne un code d'erreur non-nul (exit 1) si des alerte de haute sévérité sont trouvées (pour CI/CD)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Mode silencieux")

    args = parser.parse_args()

    if not args.quiet:
        console.print("\n[bold cyan]🛡️  DevSecAssist v0.3.0 - Audit de Sécurité Local[/bold cyan]\n")

    target_dir = Path(args.path).resolve()
    engine = ScanEngine(target_dir=target_dir, ignore_file=args.ignore_file)

    if not args.quiet:
        console.print(f"[bold]🔍 Analyse du répertoire :[/bold] [yellow]{target_dir}[/yellow]")

    # Exécution du scan centralisé
    scan_result = engine.run_scan(url=args.url)

    # Affichage console
    if not args.quiet:
        console.print(f"\n[bold]📈 Score de Sécurité Global :[/bold] [bold cyan]{scan_result.score}/100[/bold cyan] (Note : [bold green]{scan_result.risk_grade}[/bold green])")
        console.print("\n[bold]📊 Résumé des Découvertes Dédupliquées :[/bold]")
        
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Titre / Catégorie")
        table.add_column("Sévérité")
        table.add_column("Confiance")
        table.add_column("Source")
        table.add_column("Conseil")

        for finding in scan_result.findings:
            sev = finding.severity.value
            sev_color = "red" if sev == "HAUTE" else ("yellow" if sev == "MOYENNE" else "blue")
            src = finding.file or finding.target or "-"
            table.add_row(
                f"{finding.title} - {finding.category}",
                f"[{sev_color}]{sev}[/{sev_color}]",
                finding.confidence.value,
                src,
                finding.recommendation[:70] + "..."
            )

        console.print(table)

    # Génération du rapport selon le format
    output_path = Path(args.output).resolve()

    if args.format == "html":
        HTMLReporter.generate_report(scan_result, output_path)
    elif args.format == "json":
        JSONReporter.generate_report(scan_result, output_path)
    elif args.format == "sarif":
        SARIFReporter.generate_report(scan_result, output_path)

    if not args.quiet:
        console.print(f"\n[bold green]✅ Rapport [{args.format.upper()}] généré avec succès :[/bold green] [underline]{output_path}[/underline]\n")

    # Gestion de l'échec CI/CD
    if args.fail_on_high and scan_result.stats.get("high", 0) > 0:
        if not args.quiet:
            console.print(f"[bold red]❌ Échec du build CI/CD : {scan_result.stats['high']} alerte(s) de Haute Sévérité détectée(s).[/bold red]")
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
