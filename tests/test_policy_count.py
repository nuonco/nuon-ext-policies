import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from nuon_ext_policies.cli import main


class CheckPolicyCountTests(unittest.TestCase):
    def invoke(self, permission_toml: str, output: str = "text"):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        app_dir = Path(directory.name)
        permissions_dir = app_dir / "permissions"
        permissions_dir.mkdir()
        (permissions_dir / "maintenance.toml").write_text(permission_toml)
        return CliRunner().invoke(
            main,
            [
                "--app-dir",
                str(app_dir),
                "check-policy-count",
                "maintenance.toml",
                "--output",
                output,
            ],
        )

    def test_counts_named_and_aws_managed_policies_but_not_inline_policies(self):
        result = self.invoke(
            """
[[named_policies]]
name = "shared"

[[policies]]
managed_policy_name = "ReadOnlyAccess"

[[policies]]
name = "inline"
contents = "./inline.json"
""".strip(),
            output="json",
        )

        self.assertEqual(result.exit_code, 0)
        self.assertEqual(
            json.loads(result.output),
            {
                "named_policies": 1,
                "aws_managed_policies": 1,
                "total": 2,
                "max": 20,
            },
        )

    def test_passes_at_default_quota_and_emits_total(self):
        config = "\n\n".join(
            f'[[named_policies]]\nname = "policy-{index}"' for index in range(20)
        )

        result = self.invoke(config)

        self.assertEqual(result.exit_code, 0)
        self.assertIn("Managed policies: 20/20", result.output)

    def test_fails_above_default_quota_and_emits_total(self):
        config = "\n\n".join(
            f'[[named_policies]]\nname = "policy-{index}"' for index in range(21)
        )

        result = self.invoke(config)

        self.assertEqual(result.exit_code, 1)
        self.assertIn("Managed policies: 21/20", result.output)
        self.assertIn("quota is exceeded", result.output)


if __name__ == "__main__":
    unittest.main()
