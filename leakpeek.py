import typer
from rich.console import Console
from rich.table import Table
from rich.progress import track
import importlib
import os
import sys
import csv
import json
import pyfiglet
from typing import List, Optional

app = typer.Typer()
console = Console()

MODULES_DIR = os.path.join(os.path.dirname(__file__), 'modules')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output')

# ASCII Logo
@app.callback()
def main(ctx: typer.Context):
    logo = pyfiglet.figlet_format("leakpeek")
    console.print(f"[bold cyan]{logo}[/bold cyan]")

@app.command()
def list_modules():
    """List all available vulnerability modules."""
    modules = [f[:-3] for f in os.listdir(MODULES_DIR) if f.endswith('.py') and not f.startswith('__')]
    console.print("[bold green]Available Modules:[/bold green]")
    for m in modules:
        console.print(f"- {m}")

@app.command()
def scan(
    url: str = typer.Option(..., help="Target URL to scan."),
    modules: str = typer.Option("all", help="Comma-separated modules to run or 'all' for every module."),
    threads: int = typer.Option(10, help="Number of threads to use."),
    output: str = typer.Option("report.csv", help="Output file (csv or json)."),
    user_agent: Optional[str] = typer.Option(None, help="Custom User-Agent."),
    proxy: Optional[str] = typer.Option(None, help="Proxy (e.g., http://127.0.0.1:8080)."),
    wordlist: Optional[str] = typer.Option(None, help="Optional URL wordlist file.")
):
    """Scan a target for vulnerabilities."""
    # Load modules
    available = [f[:-3] for f in os.listdir(MODULES_DIR) if f.endswith('.py') and not f.startswith('__')]
    selected = available if modules == "all" else [m.strip() for m in modules.split(",") if m.strip() in available]
    if not selected:
        console.print("[red]No valid modules selected.[/red]")
        raise typer.Exit(1)

    # Prepare URLs
    urls = [url]
    if wordlist:
        with open(wordlist) as f:
            urls = [line.strip() for line in f if line.strip()]

    results = []
    for u in track(urls, description="[yellow]Scanning URLs..."):
        for mod_name in selected:
            mod = importlib.import_module(f"modules.{mod_name}")
            # Each module must have scan(url, options) -> dict
            res = mod.scan(u, user_agent=user_agent, proxy=proxy)
            if isinstance(res, list):
                results.extend(res)
            else:
                results.append(res)

    # Output table
    table = Table(title="leakpeek Scan Results")
    table.add_column("Bug Type", style="cyan")
    table.add_column("Endpoint", style="magenta")
    table.add_column("Result", style="bold")
    for r in results:
        color = "green" if r["result"].lower() == "safe" else ("yellow" if r["result"].lower() == "warning" else "red")
        table.add_row(r["type"], r["endpoint"], f"[{color}]{r['result']}[/{color}]")
    console.print(table)

    # Save output
    out_path = os.path.join(OUTPUT_DIR, output)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    if output.endswith(".csv"):
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["type", "endpoint", "result"])
            writer.writeheader()
            writer.writerows(results)
        console.print(f"[bold green]Results saved to {out_path}[/bold green]")
    elif output.endswith(".json"):
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        console.print(f"[bold green]Results saved to {out_path}[/bold green]")
    else:
        console.print("[red]Unknown output format. Use .csv or .json[/red]")

if __name__ == "__main__":
    app() 