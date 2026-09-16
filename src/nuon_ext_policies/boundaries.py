"""Compare permission boundaries across provision, deprovision, maintenance, and breakglass.

Flags discrepancies such as:
- Actions allowed in one boundary but missing in others
- Actions only present in maintenance but not in provision/deprovision
- Deny statements that differ across boundaries
"""

import json
import sys
from collections import defaultdict
from fnmatch import fnmatchcase
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from nuon_ext_policies.overlap import (
    load_json,
    load_toml,
    resolve_policy_configs,
)


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


def action_is_covered(action: str, pattern: str) -> bool:
    """Return whether a boundary action pattern covers an identity-policy action."""
    return fnmatchcase(action.lower(), pattern.lower())


def extract_allowed_actions(policy: dict) -> dict[str, set[str]]:
    """Extract only actions granted by Allow statements, grouped by Sid."""
    actions_by_sid: dict[str, set[str]] = defaultdict(set)
    for statement in policy.get("Statement", []):
        if statement.get("Effect", "Allow").lower() != "allow":
            continue
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_by_sid[statement.get("Sid", "unnamed")].update(actions)
    return dict(actions_by_sid)


def find_boundary_violations(
    policies: dict[str, dict[str, set[str]]], boundary: dict
) -> list[dict]:
    """Find policy actions that an IAM permissions boundary does not permit."""
    allowed_actions: list[tuple[str, str]] = []
    denied_actions: list[tuple[str, str]] = []

    for statement in boundary.get("Statement", []):
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        destination = (
            allowed_actions
            if statement.get("Effect", "Allow").lower() == "allow"
            else denied_actions
        )
        destination.extend((action, statement.get("Sid", "unnamed")) for action in actions)

    violations = []
    for policy_name, sids in policies.items():
        for sid, actions in sids.items():
            for action in actions:
                matching_denies = [
                    boundary_sid
                    for pattern, boundary_sid in denied_actions
                    if action_is_covered(action, pattern)
                ]
                matching_allows = [
                    boundary_sid
                    for pattern, boundary_sid in allowed_actions
                    if action_is_covered(action, pattern)
                ]
                if matching_denies:
                    violations.append(
                        {
                            "policy": policy_name,
                            "sid": sid,
                            "action": action,
                            "reason": "explicit_deny",
                            "boundary_sids": matching_denies,
                        }
                    )
                elif not matching_allows:
                    violations.append(
                        {
                            "policy": policy_name,
                            "sid": sid,
                            "action": action,
                            "reason": "not_allowed",
                            "boundary_sids": [],
                        }
                    )

    return sorted(
        violations,
        key=lambda finding: (finding["policy"], finding["action"], finding["sid"]),
    )


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


@click.command("check-policy-boundary")
@click.argument("permission_toml")
@click.option("--output", type=click.Choice(["text", "json"]), default="text", help="Output format")
@click.pass_context
def check_policy_boundary(ctx, permission_toml: str, output: str):
    """Check that a role boundary permits every inline and named policy action."""
    console = Console()
    root = Path(ctx.obj["app_dir"])
    toml_path = root / "permissions" / permission_toml

    if not toml_path.exists():
        Console(stderr=True).print(f"[red]Permission file not found: {toml_path}[/red]")
        sys.exit(1)

    config = load_toml(toml_path)
    boundary_contents = config.get("permissions_boundary")
    if not boundary_contents:
        if output == "json":
            click.echo("[]")
        else:
            console.print("[green]No permissions boundary configured.[/green]")
        return

    boundary_path = toml_path.parent / boundary_contents
    if not boundary_path.exists():
        Console(stderr=True).print(
            f"[red]Permissions boundary file not found: {boundary_path}[/red]"
        )
        sys.exit(1)

    policy_configs, missing_named_policies = resolve_policy_configs(config, toml_path)
    for name in missing_named_policies:
        Console(stderr=True).print(
            f"[yellow]Warning: Named policy definition not found: {name}[/yellow]"
        )

    policies = {}
    for policy, policy_base_dir in policy_configs:
        contents = policy.get("contents")
        if not contents:
            continue
        policy_path = policy_base_dir / contents
        if not policy_path.exists():
            Console(stderr=True).print(
                f"[yellow]Warning: Policy file not found: {policy_path}[/yellow]"
            )
            continue
        policies[policy_path.name] = extract_allowed_actions(load_json(policy_path))

    violations = find_boundary_violations(policies, load_boundary(boundary_path))
    if output == "json":
        click.echo(json.dumps(violations, indent=2))
        sys.exit(1 if violations else 0)

    if not violations:
        console.print(
            Panel(
                "[bold green]The permissions boundary allows every defined policy action.[/bold green]",
                title="Policy Boundary Result",
            )
        )
        return

    table = Table(title="Actions Blocked by Permissions Boundary")
    table.add_column("Policy", style="cyan")
    table.add_column("Sid", style="cyan")
    table.add_column("Action", style="red")
    table.add_column("Reason", style="yellow")
    table.add_column("Boundary Sid", style="magenta")
    for finding in violations:
        table.add_row(
            finding["policy"],
            finding["sid"],
            finding["action"],
            finding["reason"],
            ", ".join(finding["boundary_sids"]),
        )
    console.print(table)
    sys.exit(1)


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
