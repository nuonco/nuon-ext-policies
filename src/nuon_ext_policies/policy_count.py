"""Check AWS managed-policy attachments against the default per-role quota."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from nuon_ext_policies.overlap import load_toml


MANAGED_POLICIES_PER_ROLE = 20


def count_managed_policies(config: dict) -> dict[str, int]:
    """Count customer- and AWS-managed policies attached by a role config."""
    named = len(config.get("named_policies", []))
    aws_managed = sum(
        bool(policy.get("managed_policy_name"))
        for policy in config.get("policies", [])
    )
    return {
        "named_policies": named,
        "aws_managed_policies": aws_managed,
        "total": named + aws_managed,
        "max": MANAGED_POLICIES_PER_ROLE,
    }


@click.command("check-policy-count")
@click.argument("permission_toml")
@click.option(
    "--output",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.pass_context
def check_policy_count(ctx, permission_toml: str, output: str):
    """Check managed-policy attachments against AWS's default role quota."""
    root = Path(ctx.obj["app_dir"])
    toml_path = root / "permissions" / permission_toml

    if not toml_path.exists():
        Console(stderr=True).print(f"[red]Permission file not found: {toml_path}[/red]")
        sys.exit(1)

    result = count_managed_policies(load_toml(toml_path))
    over_limit = result["total"] > result["max"]

    if output == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        color = "red" if over_limit else "green"
        message = (
            f"[{color}]Managed policies: {result['total']}/{result['max']}[/{color}]\n"
            f"Named: {result['named_policies']}  AWS managed: "
            f"{result['aws_managed_policies']}"
        )
        if over_limit:
            message += "\n[red]AWS's default managed-policies-per-role quota is exceeded.[/red]"
        Console().print(Panel(message, title="Managed Policy Count"))

    sys.exit(1 if over_limit else 0)
