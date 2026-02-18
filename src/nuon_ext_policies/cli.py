import click

from nuon_ext_policies.boundaries import check_boundaries
from nuon_ext_policies.overlap import check_overlap
from nuon_ext_policies.diagram import generate_diagram


@click.group()
@click.version_option(package_name="nuon-ext-policies")
def main():
    """Validate and analyze Nuon permission policies and boundaries."""
    pass


main.add_command(check_boundaries)
main.add_command(check_overlap)
main.add_command(generate_diagram)
