# Nuon Extension: policies

Validate and analyze Nuon permission policies and boundaries.

## Installation

```bash
nuon ext install nuonco/nuon-ext-policies
```

## Usage

Run commands from your Nuon app directory, or pass `--app-dir` to point at one:

```bash
nuon policies --app-dir /path/to/app <command>
```

### `check-overlap`

Check for overlapping IAM actions across policy documents in a permission TOML file. The filename is resolved under
`permissions/`.

```bash
nuon policies check-overlap maintenance.toml
```

Use `--output json` for machine-readable output:

```bash
nuon policies check-overlap maintenance.toml --output json
```

### `check-boundaries`

Compare permission boundaries across provision, deprovision, maintenance, and breakglass. Automatically discovers
boundary JSON files in `permissions/`.

```bash
nuon policies check-boundaries
```

Use `--output json` for machine-readable output:

```bash
nuon policies check-boundaries --output json
```

## Development

```bash
git clone https://github.com/nuon/nuon-ext-policies.git
cd nuon-ext-policies
uv sync
```

Run commands locally:

```bash
uv run nuon-ext-policies --help
uv run nuon-ext-policies --app-dir ../my-app check-overlap maintenance.toml
uv run nuon-ext-policies --app-dir ../my-app check-boundaries
```
