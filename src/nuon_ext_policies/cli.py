from pathlib import Path

import click

from nuon_ext_policies.boundaries import check_boundaries, check_policy_boundary
from nuon_ext_policies.overlap import check_overlap
from nuon_ext_policies.policy_count import check_policy_count


@click.group(context_settings={"max_content_width": 100})
@click.version_option(package_name="nuon-ext-policies")
@click.option(
    "--app-dir",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    metavar="DIRECTORY",
    help="Nuon app directory containing permissions/. Defaults to the current directory.",
)
@click.pass_context
def main(ctx, app_dir):
    """Audit IAM policies and permission boundaries in a Nuon app.

    Run this extension from the app directory, or pass --app-dir before the
    subcommand. Permission-file arguments are filenames relative to
    APP_DIR/permissions/, not arbitrary paths.

    Use --output json on a subcommand for machine-readable stdout. Diagnostics
    are written to stderr. Exit status 0 means the check passed; status 1 means
    the check found a failing condition or could not read required input;
    status 2 means the command invocation was invalid.

    \b
    Agent workflow:
      nuon policies --app-dir <app> check-policy-count maintenance.toml --output json
      nuon policies --app-dir <app> check-overlap maintenance.toml --output json
      nuon policies --app-dir <app> check-policy-boundary maintenance.toml --output json
      nuon policies --app-dir <app> check-boundaries --output json

    Run each role-file command for every applicable permission TOML (for
    example provision.toml, deprovision.toml, maintenance.toml, and
    breakglass.toml).
    """
    ctx.ensure_object(dict)
    resolved_app_dir = Path.cwd() if app_dir is None else Path(app_dir).resolve()
    ctx.obj["app_dir"] = str(resolved_app_dir)


main.add_command(check_boundaries)
main.add_command(check_overlap)
main.add_command(check_policy_boundary)
main.add_command(check_policy_count)
