from __future__ import annotations

import unittest

from experiments.pi_smoke import EXPECTED_ARGUMENTS, EXPECTED_SUMMARY, validate_example_run
from tara_maintenance.baseline import JsonObject


class PiSmokeValidationTests(unittest.TestCase):
    report: JsonObject
    events: list[JsonObject]

    def setUp(self) -> None:
        self.report: JsonObject = {
            "summary": dict(EXPECTED_SUMMARY),
            "recommendations": [
                {
                    "change_id": "VULN-1",
                    "vulnerability_id": "CVE-2026-0001",
                    "decision": "review_required",
                }
            ],
        }
        self.events = [
            {
                "type": "tool_execution_start",
                "toolName": "tara_maintenance",
                "args": dict(EXPECTED_ARGUMENTS),
            },
            {
                "type": "tool_execution_end",
                "toolName": "tara_maintenance",
                "result": {"content": []},
            },
            {
                "type": "message_end",
                "message": {
                    "role": "assistant",
                    "stopReason": "stop",
                    "content": [
                        {
                            "type": "text",
                            "text": "VULN-1 CVE-2026-0001 review_required",
                        }
                    ],
                },
            },
        ]

    def test_valid_tool_run_and_response_pass(self) -> None:
        self.assertEqual(validate_example_run(self.events, self.report), [])

    def test_wrong_example_path_fails(self) -> None:
        self.events[0]["args"] = {
            **EXPECTED_ARGUMENTS,
            "changes_path": "data/changes.json",
        }

        failures = validate_example_run(self.events, self.report)

        self.assertTrue(any("Incorrect tool arguments" in failure for failure in failures))

    def test_missing_tool_call_fails(self) -> None:
        failures = validate_example_run(self.events[2:], self.report)

        self.assertIn("Expected exactly one complete tool call", failures[0])

    def test_editorial_identifier_correction_fails(self) -> None:
        self.events[2]["message"]["content"][0]["text"] = (
            "VULN-1 CVE-2026-0002? No — CVE-2026-0001 review_required"
        )

        failures = validate_example_run(self.events, self.report)

        self.assertTrue(any("questioned CVE" in failure for failure in failures))

    def test_unsupported_truncation_claim_fails(self) -> None:
        self.events[1]["result"]["details"] = {"truncated": False}
        self.events[2]["message"]["content"][0]["text"] += "; output was truncated"

        failures = validate_example_run(self.events, self.report)

        self.assertTrue(any("truncation claim" in failure for failure in failures))

    def test_incomplete_cpe_evidence_fails(self) -> None:
        self.report["recommendations"][0]["evidence"] = {
            "matched_software": [
                {"cpe": "cpe:2.3:a:example:product:1.0:*:*:*:*:*:*:*"}
            ]
        }
        self.events[2]["message"]["content"][0]["text"] += (
            "; matched cpe:2.3:a:example:product:1.0"
        )

        failures = validate_example_run(self.events, self.report)

        self.assertTrue(any("unsupported CPE" in failure for failure in failures))

    def test_component_match_cannot_be_described_as_cpe_match(self) -> None:
        self.report["recommendations"][0]["evidence"] = {
            "matched_components": [
                {"component_id": "COMP-1", "matched_by": ["affected_components"]}
            ],
            "matched_software": [],
        }
        self.events[2]["message"]["content"][0]["text"] += "; matched by exact CPE"

        failures = validate_example_run(self.events, self.report)

        self.assertTrue(any("false CPE matching claim" in failure for failure in failures))

    def test_wildcard_cpe_from_range_evidence_is_accepted(self) -> None:
        wildcard = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        self.report["recommendations"][0]["evidence"] = {
            "matched_cpe_rules": [{"cpe": wildcard}],
            "matched_software": [],
        }
        self.events[2]["message"]["content"][0]["text"] += f"; rule {wildcard}"

        self.assertEqual(validate_example_run(self.events, self.report), [])

    def test_unresolved_cpe_with_sentence_punctuation_is_accepted(self) -> None:
        wildcard = "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"
        self.report["recommendations"][0]["evidence"] = {
            "matched_software": [],
            "unresolved_identifiers": {"cpes": [wildcard]},
        }
        self.events[2]["message"]["content"][0]["text"] += f"; unresolved {wildcard},"

        self.assertEqual(validate_example_run(self.events, self.report), [])


if __name__ == "__main__":
    unittest.main()
