import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from nuon_ext_policies.cli import main


class CheckOverlapTests(unittest.TestCase):
    def test_empty_policy_config_returns_an_object(self):
        with tempfile.TemporaryDirectory() as directory:
            app_dir = Path(directory)
            permissions_dir = app_dir / "permissions"
            permissions_dir.mkdir()
            (permissions_dir / "maintenance.toml").write_text("")

            result = CliRunner().invoke(
                main,
                [
                    "--app-dir",
                    str(app_dir),
                    "check-overlap",
                    "maintenance.toml",
                    "--output",
                    "json",
                ],
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(json.loads(result.output), {})

    def test_includes_referenced_named_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            app_dir = Path(directory)
            permissions_dir = app_dir / "permissions"
            policies_dir = permissions_dir / "policies"
            policies_dir.mkdir(parents=True)

            (permissions_dir / "maintenance.toml").write_text(
                """
[[named_policies]]
name = "shared-maintenance"

[[policies]]
name = "inline-maintenance"
contents = "./inline.json"
""".strip()
            )
            (policies_dir / "shared.toml").write_text(
                'name = "shared-maintenance"\ncontents = "./shared.json"\n'
            )
            (permissions_dir / "inline.json").write_text(
                json.dumps(
                    {"Statement": [{"Sid": "Inline", "Action": ["s3:GetObject"]}]}
                )
            )
            (policies_dir / "shared.json").write_text(
                json.dumps(
                    {
                        "Statement": [
                            {
                                "Sid": "Named",
                                "Action": ["s3:GetObject", "s3:ListBucket"],
                            }
                        ]
                    }
                )
            )

            result = CliRunner().invoke(
                main,
                [
                    "--app-dir",
                    str(app_dir),
                    "check-overlap",
                    "maintenance.toml",
                    "--output",
                    "json",
                ],
            )

            self.assertEqual(result.exit_code, 1)
            overlaps = json.loads(result.output)
            self.assertEqual(set(overlaps), {"s3:GetObject"})
            self.assertEqual(
                overlaps["s3:GetObject"],
                [
                    {
                        "policy1": "inline.json",
                        "sid1": "Inline",
                        "policy2": "shared.json",
                        "sid2": "Named",
                    }
                ],
            )


if __name__ == "__main__":
    unittest.main()
