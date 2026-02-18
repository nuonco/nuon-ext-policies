"""Generate a Mermaid dependency diagram from Nuon component TOML files."""

import re
import sys
from pathlib import Path

import click
import tomli


def get_dependencies(content: str) -> set[str]:
    """Extract component names referenced via .nuon.components.<name>.outputs."""
    pattern = r"\.nuon\.components\.([a-zA-Z0-9_-]+)\.outputs"
    return set(re.findall(pattern, content))


@click.command("generate-diagram")
@click.argument("components_dir", type=click.Path(exists=True, file_okay=False))
def generate_diagram(components_dir: str):
    """Generate a Mermaid dependency diagram of components.

    COMPONENTS_DIR is the directory containing component TOML files.
    """
    components_path = Path(components_dir)
    toml_files = sorted(components_path.glob("*.toml"))

    if not toml_files:
        click.echo(f"No TOML files found in {components_dir}", err=True)
        sys.exit(1)

    components: dict[str, dict] = {}

    for file_path in toml_files:
        try:
            with open(file_path, "rb") as f:
                data = tomli.load(f)

            name = data.get("name")
            comp_type = data.get("type")
            if not name:
                continue

            components[name] = {
                "type": comp_type,
                "file": file_path.name,
                "deps": set(),
            }

            # Check [vars] block
            vars_block = data.get("vars", {})
            for key, value in vars_block.items():
                if isinstance(value, str):
                    components[name]["deps"].update(get_dependencies(value))

            # Check [[var_file]] block
            var_files = data.get("var_file", [])
            for vf in var_files:
                contents_path = vf.get("contents")
                if contents_path:
                    full_path = file_path.parent / contents_path
                    if full_path.exists():
                        file_content = full_path.read_text()
                        components[name]["deps"].update(get_dependencies(file_content))
                    else:
                        click.echo(
                            f"Warning: var_file {full_path} not found for component {name}",
                            err=True,
                        )

        except Exception as e:
            click.echo(f"Error parsing {file_path}: {e}", err=True)

    # Generate Mermaid chart
    click.echo("```mermaid")
    click.echo("graph TD")

    for name, info in components.items():
        label = f"{name}<br/>{info['file']}"
        click.echo(f'  {name}["{label}"]')

    click.echo()

    for name, info in components.items():
        for dep in info["deps"]:
            if dep in components:
                click.echo(f"  {dep} --> {name}")

    click.echo()

    tf_components = [n for n, i in components.items() if i["type"] != "container_image"]
    img_components = [n for n, i in components.items() if i["type"] == "container_image"]

    if tf_components:
        click.echo(f"  class {','.join(tf_components)} tfClass;")
    if img_components:
        click.echo(f"  class {','.join(img_components)} imgClass;")

    click.echo()
    click.echo("  classDef tfClass fill:#D6B0FC,stroke:#8040BF,color:#000;")
    click.echo("  classDef imgClass fill:#FCA04A,stroke:#CC803A,color:#000;")
    click.echo("```")
