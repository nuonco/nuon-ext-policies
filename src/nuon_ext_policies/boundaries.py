"""Compare permission boundaries across provision, deprovision, maintenance, and breakglass.

Flags discrepancies such as:
- Actions allowed in one boundary but missing in others
- Actions only present in maintenance but not in provision/deprovision
- Deny statements that differ across boundaries
"""

import json
import sys
from collections import defaultdict
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def load_boundary(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def expand_actions(statements: list) -> dict[str, set[str]]:
    """Extract actions by effect (Allow/Deny) from statements."""
    by_effect: dict[str, set[str]] = defaultdict(set)
    for stmt in statements:
        effect = stmt.get("Effect", "Allow")
        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        for action in actions:
            by_effect[effect].add(action)
    return dict(by_effect)


def normalize_action(action: str) -> str:
    """Normalize action for comparison (lowercase service prefix)."""
    if ":" in action:
        service, op = action.split(":", 1)
        return f"{service.lower()}:{op}"
    return action.lower()


def compare_boundaries(boundaries: dict[str, dict]) -> list[dict]:
    """Compare all boundaries and return discrepancies."""
    findings = []

    all_actions = {}
    for name, data in boundaries.items():
        statements = data.get("Statement", [])
        all_actions[name] = expand_actions(statements)

    # Build action -> {boundary: effect} mapping
    action_map: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
    for name, effects in all_actions.items():
        for effect, actions in effects.items():
            for action in actions:
                norm = normalize_action(action)
                action_map[(norm, effect)][name] = action

    boundary_names = list(boundaries.keys())

    for (norm_action, effect), present_in in sorted(action_map.items()):
        missing_from = [b for b in boundary_names if b not in present_in]

        if not missing_from:
            continue

        maintenance_only = (
            "maintenance" in present_in
            and "provision" not in present_in
            and "deprovision" not in present_in
        )
        breakglass_only = present_in.keys() == {"breakglass"}

        finding = {
            "action": list(present_in.values())[0],
            "normalized": norm_action,
            "effect": effect,
            "present_in": list(present_in.keys()),
            "missing_from": missing_from,
            "severity": "high"
            if maintenance_only
            else ("low" if breakglass_only else "medium"),
            "note": "",
        }

        if maintenance_only:
            finding["note"] = (
                "Maintenance allows this but provision/deprovision do not!"
            )
        elif breakglass_only:
            finding["note"] = "Breakglass-only (expected for emergency access)"
        elif "provision" in missing_from or "deprovision" in missing_from:
            finding["note"] = "Missing from core lifecycle boundaries"

        findings.append(finding)

    return findings


def print_findings_table(console: Console, severity: str, items: list[dict]):
    """Print findings as a rich table."""
    table = Table(title=f"{severity.upper()} PRIORITY ({len(items)} findings)")
    table.add_column("Action", style="cyan")
    table.add_column("Effect", style="green")
    table.add_column("Present In", style="green")
    table.add_column("Missing From", style="red")
    table.add_column("Note", style="dim")

    for f in items:
        table.add_row(
            f["action"],
            f["effect"],
            ", ".join(f["present_in"]),
            ", ".join(f["missing_from"]),
            f["note"],
        )

    console.print(table)
    console.print()


@click.command("check-boundaries")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.pass_context
def check_boundaries(ctx, output: str):
    """Compare permission boundaries for discrepancies.

    Searches for a permissions/ directory in the app config directory.
    """
    console = Console()
    root = Path(ctx.obj["app_dir"])
    permissions_path = root / "permissions"

    if not permissions_path.is_dir():
        Console(stderr=True).print("[red]No permissions/ directory found.[/red]")
        sys.exit(1)

    boundary_files = {
        "provision": permissions_path / "provision_boundary.json",
        "deprovision": permissions_path / "deprovision_boundary.json",
        "maintenance": permissions_path / "maintenance_boundary.json",
        "breakglass": permissions_path / "breakglass_boundary.json",
    }

    if output != "json":
        console.print(
            Panel("Loading Permission Boundaries", title="Boundary Checker")
        )

    boundaries = {}
    for name, path in boundary_files.items():
        if path.exists():
            boundaries[name] = load_boundary(path)
            if output != "json":
                console.print(
                    f"  [green]✓[/green] Loaded [cyan]{name}[/cyan]: {path.name}"
                )
        else:
            if output != "json":
                console.print(
                    f"  [red]✗[/red] Missing [cyan]{name}[/cyan]: {path}"
                )

    if output != "json":
        console.print()

    findings = compare_boundaries(boundaries)

    if output == "json":
        import json as json_mod

        click.echo(json_mod.dumps(findings, indent=2))
        sys.exit(1 if any(f["severity"] == "high" for f in findings) else 0)

    if not findings:
        console.print(
            Panel(
                "[bold green]All boundaries are consistent![/bold green]",
                title="Result",
            )
        )
        return

    by_severity: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        by_severity[f["severity"]].append(f)

    exit_code = 0
    for severity in ["high", "medium", "low"]:
        items = by_severity.get(severity, [])
        if items:
            print_findings_table(console, severity, items)
            if severity == "high":
                exit_code = 1

    console.print(
        Panel(
            Text.assemble(
                ("Total discrepancies: ", "bold"),
                (str(len(findings)), "bold red"),
                ("\n  High: ", ""),
                (str(len(by_severity["high"])), "red"),
                ("  Medium: ", ""),
                (str(len(by_severity["medium"])), "yellow"),
                ("  Low: ", ""),
                (str(len(by_severity["low"])), "blue"),
            ),
            title="Summary",
        )
    )

    sys.exit(exit_code)
