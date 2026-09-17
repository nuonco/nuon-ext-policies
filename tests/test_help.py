import unittest

from click.testing import CliRunner

from nuon_ext_policies.cli import main


class HelpTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def assert_help_contains(self, command: list[str], expected: list[str]):
        result = self.runner.invoke(main, [*command, "--help"])

        self.assertEqual(result.exit_code, 0, result.output)
        normalized_output = " ".join(result.output.split())
        for text in expected:
            self.assertIn(" ".join(text.split()), normalized_output)

    def test_top_level_help_explains_agent_contract(self):
        self.assert_help_contains(
            [],
            [
                "APP_DIR/permissions/",
                "--output json",
                "Exit status 0",
                "status 2 means the command invocation was invalid",
                "Agent workflow:",
                "check-policy-boundary maintenance.toml --output json",
            ],
        )

    def test_role_checks_explain_input_output_and_exit_status(self):
        expectations = {
            "check-overlap": [
                "APP_DIR/permissions/PERMISSION_FILE",
                "does not expand IAM wildcards",
                "empty object means no overlaps",
                "Exit status is 1 when overlaps are found",
            ],
            "check-policy-count": [
                "managed_policy_name",
                "Inline policies with contents do not count",
                "20/20 passes",
            ],
            "check-policy-boundary": [
                "supports IAM-style * and ? wildcards",
                "Resource and Condition",
                "absent permissions_boundary passes",
            ],
        }
        for command, expected in expectations.items():
            with self.subTest(command=command):
                self.assert_help_contains([command], expected)

    def test_boundary_comparison_help_explains_files_and_severity(self):
        self.assert_help_contains(
            ["check-boundaries"],
            [
                "provision_boundary.json",
                "Maintenance-only actions are high severity",
                "medium- and low-severity findings alone return 0",
            ],
        )


if __name__ == "__main__":
    unittest.main()
