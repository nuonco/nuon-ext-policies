import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from nuon_ext_policies.boundaries import find_boundary_violations
from nuon_ext_policies.cli import main


class PolicyBoundaryTests(unittest.TestCase):
    def test_finds_actions_missing_from_allow_and_explicitly_denied(self):
        policies = {
            "inline.json": {
                "Objects": {"s3:GetObject", "s3:DeleteObject"},
            },
            "named.json": {
                "Instances": {"ec2:DescribeInstances"},
            },
        }
        boundary = {
            "Statement": [
                {"Sid": "S3Read", "Effect": "Allow", "Action": "s3:Get*"},
                {"Sid": "EC2", "Effect": "Allow", "Action": "ec2:*"},
                {
                    "Sid": "NoDescribe",
                    "Effect": "Deny",
                    "Action": "ec2:DescribeInstances",
                },
            ]
        }

        self.assertEqual(
            find_boundary_violations(policies, boundary),
            [
                {
                    "policy": "inline.json",
                    "sid": "Objects",
                    "action": "s3:DeleteObject",
                    "reason": "not_allowed",
                    "boundary_sids": [],
                },
                {
                    "policy": "named.json",
                    "sid": "Instances",
                    "action": "ec2:DescribeInstances",
                    "reason": "explicit_deny",
                    "boundary_sids": ["NoDescribe"],
                },
            ],
        )

    def test_command_checks_inline_and_named_policies(self):
        with tempfile.TemporaryDirectory() as directory:
            app_dir = Path(directory)
            permissions_dir = app_dir / "permissions"
            policies_dir = permissions_dir / "policies"
            policies_dir.mkdir(parents=True)

            (permissions_dir / "maintenance.toml").write_text(
                """
permissions_boundary = "./boundary.json"

[[named_policies]]
name = "shared"

[[policies]]
name = "inline"
contents = "./inline.json"
""".strip()
            )
            (policies_dir / "shared.toml").write_text(
                'name = "shared"\ncontents = "./shared.json"\n'
            )
            (permissions_dir / "boundary.json").write_text(
                json.dumps(
                    {
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:Get*"},
                        ]
                    }
                )
            )
            (permissions_dir / "inline.json").write_text(
                json.dumps(
                    {
                        "Statement": [
                            {"Sid": "Inline", "Action": "s3:PutObject"},
                            {
                                "Sid": "Guardrail",
                                "Effect": "Deny",
                                "Action": "dynamodb:DeleteTable",
                            },
                        ]
                    }
                )
            )
            (policies_dir / "shared.json").write_text(
                json.dumps(
                    {"Statement": [{"Sid": "Named", "Action": "sqs:GetQueueUrl"}]}
                )
            )

            result = CliRunner().invoke(
                main,
                [
                    "--app-dir",
                    str(app_dir),
                    "check-policy-boundary",
                    "maintenance.toml",
                    "--output",
                    "json",
                ],
            )

            self.assertEqual(result.exit_code, 1)
            violations = json.loads(result.output)
            self.assertEqual(
                {(item["policy"], item["action"]) for item in violations},
                {("inline.json", "s3:PutObject"), ("shared.json", "sqs:GetQueueUrl")},
            )

    def test_command_passes_without_a_boundary(self):
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
                    "check-policy-boundary",
                    "maintenance.toml",
                    "--output",
                    "json",
                ],
            )

            self.assertEqual(result.exit_code, 0)
            self.assertEqual(json.loads(result.output), [])


if __name__ == "__main__":
    unittest.main()
