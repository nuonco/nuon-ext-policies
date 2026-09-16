# Nuon Extension: policies

Validate and analyze Nuon permission policies and boundaries.

## Installation

```bash
nuon ext install nuonco/nuon-ext-policies
```

## Usage

Run commands from your Nuon app directory. If `--app-dir` is omitted, it implicitly uses the current working directory:

```bash
nuon policies --app-dir /path/to/app <command>
```

### `check-overlap`

Check for overlapping IAM actions across policy documents attached to a role in a permission TOML file. The filename is
resolved under `permissions/`.

The check includes both inline `[[policies]]` entries and `[[named_policies]]` references. Named policy definitions are
loaded by matching `name` exactly against `permissions/policies/*.toml`; each definition's `contents` path is resolved
relative to `permissions/policies/`.

```bash
nuon policies check-overlap maintenance.toml
```

Use `--output json` for machine-readable output:

```bash
nuon policies check-overlap maintenance.toml --output json
```

### `check-policy-count`

Check the number of managed policies attached to a role against AWS's default quota of 20. The total includes both
`[[named_policies]]` references and `[[policies]]` entries with `managed_policy_name`; inline policies do not count.

```bash
nuon policies check-policy-count maintenance.toml
```

The command always emits the total as `n/20` and exits nonzero when the total exceeds 20. Use `--output json` for a
machine-readable count and breakdown.

### `check-policy-boundary`

Check that an optional IAM permissions boundary allows every action defined by a role's inline and named policies.
Action matching is case-insensitive and supports IAM wildcards. A missing boundary imposes no restriction and passes.

```bash
nuon policies check-policy-boundary maintenance.toml
```

This check compares actions only. AWS still evaluates each statement's resources and conditions at runtime.

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
uv run nuon-ext-policies --app-dir ../my-app check-policy-count maintenance.toml
uv run nuon-ext-policies --app-dir ../my-app check-policy-boundary maintenance.toml
uv run nuon-ext-policies --app-dir ../my-app check-boundaries
uv run python -m unittest discover -s tests
```
