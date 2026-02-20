from pathlib import Path

import click

from nuon_ext_policies.boundaries import check_boundaries
from nuon_ext_policies.overlap import check_overlap


@click.group()
@click.version_option(package_name="nuon-ext-policies")
@click.option(
    "--app-dir",
    type=click.Path(exists=True, file_okay=False),
    default=".",
    help="Path to the Nuon app configuration directory.",
)
@click.pass_context
def main(ctx, app_dir):
    """Validate and analyze Nuon permission policies and boundaries."""
    ctx.ensure_object(dict)
    ctx.obj["app_dir"] = str(Path.cwd() / app_dir)


main.add_command(check_boundaries)
main.add_command(check_overlap)
