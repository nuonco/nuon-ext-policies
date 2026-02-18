"""Check for overlapping IAM actions across policy documents in a Nuon permission TOML file."""

import json
import sys
from collections import defaultdict
from pathlib import Path

import click
import tomli
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def load_toml(path: Path) -> dict:
    with open(path, "rb") as f:
        return tomli.load(f)


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def extract_actions(policy: dict) -> dict[str, set[str]]:
    """Extract actions from a policy document, grouped by Sid."""
    actions_by_sid: dict[str, set[str]] = {}
    for statement in policy.get("Statement", []):
        sid = statement.get("Sid", "unnamed")
        actions = statement.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]
        actions_by_sid[sid] = set(actions)
    return actions_by_sid


def find_overlaps(
    policies: dict[str, dict[str, set[str]]],
) -> dict[str, list[tuple[str, str, str, str]]]:
    """Find overlapping actions between policies.

    Returns a dict mapping action -> list of (policy1, sid1, policy2, sid2) tuples.
    """
    action_sources: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for policy_name, sids in policies.items():
        for sid, actions in sids.items():
            for action in actions:
                action_sources[action].append((policy_name, sid))

    overlaps: dict[str, list[tuple[str, str, str, str]]] = {}
    for action, sources in action_sources.items():
        if len(sources) > 1:
            unique_policies = set(p for p, _ in sources)
            if len(unique_policies) > 1:
                pairs = []
                for i, (p1, s1) in enumerate(sources):
                    for p2, s2 in sources[i + 1 :]:
                        if p1 != p2:
                            pairs.append((p1, s1, p2, s2))
                if pairs:
                    overlaps[action] = pairs

    return overlaps


@click.command("check-overlap")
@click.argument("permission_toml", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-output", is_flag=True, help="Output results as JSON")
def check_overlap(permission_toml: str, json_output: bool):
    """Check for overlapping IAM actions across policy documents.

    PERMISSION_TOML is the path to a permission TOML file
    (e.g. permissions/maintenance.toml)
    """
    console = Console()
    toml_path = Path(permission_toml)

    config = load_toml(toml_path)
    policies_config = config.get("policies", [])

    if not policies_config:
        if json_output:
            click.echo("[]")
        else:
            console.print(
                "[yellow]No [[policies]] blocks found in the TOML file.[/yellow]"
            )
        return

    if not json_output:
        console.print(
            Panel(f"Analyzing [bold]{toml_path}[/bold]", title="Policy Overlap Checker")
        )

    base_dir = toml_path.parent
    policies: dict[str, dict[str, set[str]]] = {}

    if not json_output:
        table = Table(title="Policy Documents")
        table.add_column("Policy Name", style="cyan")
        table.add_column("File", style="green")
        table.add_column("Statements", justify="right")
        table.add_column("Actions", justify="right")

    for policy in policies_config:
        name = policy.get("name", "unnamed")
        contents_path = policy.get("contents", "")
        json_path = base_dir / contents_path

        if not json_path.exists():
            if not json_output:
                console.print(
                    f"[yellow]Warning: Policy file not found: {json_path}[/yellow]"
                )
            continue

        try:
            policy_doc = load_json(json_path)
            actions_by_sid = extract_actions(policy_doc)
            policies[json_path.name] = actions_by_sid

            if not json_output:
                total_actions = sum(len(a) for a in actions_by_sid.values())
                table.add_row(
                    name.replace("{{.nuon.install.id}}", "<install>"),
                    json_path.name,
                    str(len(actions_by_sid)),
                    str(total_actions),
                )
        except json.JSONDecodeError as e:
            if not json_output:
                console.print(f"[red]Error parsing {json_path}: {e}[/red]")

    if not json_output:
        console.print(table)
        console.print()

    overlaps = find_overlaps(policies)

    if json_output:
        result = {
            action: [
                {"policy1": p1, "sid1": s1, "policy2": p2, "sid2": s2}
                for p1, s1, p2, s2 in pairs
            ]
            for action, pairs in overlaps.items()
        }
        click.echo(json.dumps(result, indent=2))
        sys.exit(1 if overlaps else 0)

    if not overlaps:
        console.print(
            Panel(
                "[bold green]No overlapping actions found between policies.[/bold green]",
                title="Result",
            )
        )
        return

    console.print(
        Panel(
            f"[bold yellow]Found {len(overlaps)} overlapping action(s)[/bold yellow]",
            title="Overlap Report",
        )
    )

    # Group overlaps by policy pair
    pair_overlaps: dict[tuple[str, str], list[tuple[str, str, str]]] = defaultdict(list)
    for action, pairs in overlaps.items():
        for p1, s1, p2, s2 in pairs:
            key = tuple(sorted([p1, p2]))
            pair_overlaps[key].append(
                (action, s1 if p1 == key[0] else s2, s2 if p1 == key[0] else s1)
            )

    for (p1, p2), actions in sorted(pair_overlaps.items()):
        overlap_table = Table(title=f"{p1} ↔ {p2}")
        overlap_table.add_column("Action", style="red")
        overlap_table.add_column(f"Sid in {p1}", style="cyan")
        overlap_table.add_column(f"Sid in {p2}", style="cyan")

        for action, s1, s2 in sorted(actions):
            overlap_table.add_row(action, s1, s2)

        console.print(overlap_table)
        console.print()

    console.print(
        Panel(
            Text.assemble(
                ("Total overlapping actions: ", "bold"),
                (str(len(overlaps)), "bold red"),
                ("\nPolicy pairs with overlaps: ", "bold"),
                (str(len(pair_overlaps)), "bold yellow"),
            ),
            title="Summary",
        )
    )

    sys.exit(1)
