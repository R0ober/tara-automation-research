from __future__ import annotations

import copy
import unittest
from pathlib import Path

from tara_maintenance import InputError, MaintenanceBaseline, evaluate_changes, load_json

MAINTENANCE_DIR = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = MAINTENANCE_DIR.parent
TARA_PATH = (
    REPOSITORY_ROOT / "shared" / "reference-tara" / "bbw" / "reference-tara.json"
)
ARCHITECTURE_PATH = (
    REPOSITORY_ROOT / "shared" / "architecture" / "bbw" / "item-definition.json"
)


class MaintenanceBaselineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.architecture = {
            "item_definition": {"item_id": "ITEM-1"},
            "components": [
                {
                    "component_id": "COMP-VDCM",
                    "name": "Vehicle domain controller",
                    "os": {
                        "name": "Linux",
                        "kernel_version": "5.10.70",
                        "cpe": "cpe:2.3:o:linux:linux_kernel:5.10.70:*:*:*:*:*:*:*",
                    },
                    "hosted_software": [
                        {
                            "name": "bluez",
                            "version": "5.54",
                            "cpe": "cpe:2.3:a:bluez:bluez:5.54:*:*:*:*:*:*:*",
                        }
                    ],
                },
                {"component_id": "COMP-EBCM", "name": "Brake controller"},
            ],
        }
        self.tara = {
            "tara_metadata": {
                "document_id": "TARA-1",
                "version": "1",
                "item_id": "ITEM-1",
            },
            "threat_scenarios_and_attack_trees": [
                {
                    "threat_scenario_id": "TS-1",
                    "targeted_asset": {"parent_component": "COMP-VDCM"},
                    "attack_tree": {
                        "node_id": "ROOT-1",
                        "title": "Compromise braking",
                        "children": [
                            {
                                "node_id": "LEAF-1",
                                "title": "Exploit BlueZ",
                                "target_component": "COMP-VDCM",
                                "vulnerability_reference": "CVE-2020-12351 in BlueZ",
                            }
                        ],
                    },
                }
            ],
        }
        self.baseline = MaintenanceBaseline(self.tara, self.architecture)

    @staticmethod
    def vulnerability(change_id: str = "VULN-1", **overrides: object) -> dict:
        change = {
            "change_id": change_id,
            "type": "vulnerability",
            "cve_id": "CVE-2026-0001",
            "affected_components": ["COMP-VDCM"],
            "source": "unit-test feed",
            "source_url": "https://example.invalid/vulnerability",
        }
        change.update(overrides)
        return change

    def evaluate_one(self, change: dict) -> dict:
        report = self.baseline.evaluate({"changes": [change]})
        self.assertEqual(report["summary"]["total"], 1)
        return report["recommendations"][0]

    def test_new_vulnerability_for_known_component_requires_review(self) -> None:
        result = self.evaluate_one(self.vulnerability())

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(result["vulnerability_id"], "CVE-2026-0001")
        self.assertEqual(result["evidence"]["related_threat_scenarios"], ["TS-1"])
        self.assertEqual(
            result["evidence"]["related_attack_steps"][0]["node_id"], "LEAF-1"
        )
        self.assertEqual(
            result["evidence"]["source"]["url"],
            "https://example.invalid/vulnerability",
        )

    def test_existing_vulnerability_is_not_flagged_again(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(cve_id="cve-2020-12351")
        )

        self.assertEqual(result["decision"], "no_review")
        self.assertEqual(result["vulnerability_id"], "CVE-2020-12351")
        self.assertEqual(
            result["evidence"]["existing_vulnerability_references"][0]["node_id"],
            "LEAF-1",
        )

    def test_existing_vulnerability_matched_only_by_cpe_is_not_flagged_again(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(
                cve_id="CVE-2020-12351",
                affected_components=[],
                affected_cpes=["cpe:2.3:a:bluez:bluez:5.54:*:*:*:*:*:*:*"],
            )
        )

        self.assertEqual(result["decision"], "no_review")
        self.assertEqual(
            result["evidence"]["matched_components"][0]["component_id"],
            "COMP-VDCM",
        )
        self.assertEqual(
            result["evidence"]["existing_vulnerability_references"][0]["node_id"],
            "LEAF-1",
        )

    def test_existing_vulnerability_with_version_exclusion_requires_review(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(
                cve_id="CVE-2020-12351",
                affected_components=[],
                affected_cpe_ranges=[
                    {
                        "cpe": "cpe:2.3:a:bluez:bluez:*:*:*:*:*:*:*:*",
                        "version_end_including": "5.53",
                    }
                ],
            )
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertTrue(result["evidence"]["existing_vulnerability_references"])
        self.assertTrue(result["evidence"]["excluded_software"])

    def test_existing_vulnerability_for_other_component_requires_review(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(
                cve_id="CVE-2020-12351",
                affected_components=["COMP-EBCM"],
            )
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(
            result["evidence"]["matched_components"][0]["component_id"],
            "COMP-EBCM",
        )
        self.assertEqual(
            result["evidence"]["existing_vulnerability_references"][0]["node_id"],
            "LEAF-1",
        )
        self.assertIn(
            "not referenced by the existing TARA for any affected component",
            result["rationale"],
        )

    def test_non_string_tara_index_fields_raise_input_errors(self) -> None:
        cases = {
            "target_component": {"id": "COMP-VDCM"},
            "vulnerability_reference": 123,
            "parent_component": ["COMP-VDCM"],
            "tara_metadata": ["invalid"],
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                tara = copy.deepcopy(self.tara)
                if field == "tara_metadata":
                    tara[field] = value
                elif field == "parent_component":
                    tara["threat_scenarios_and_attack_trees"][0]["targeted_asset"][
                        field
                    ] = value
                else:
                    tara["threat_scenarios_and_attack_trees"][0]["attack_tree"][
                        "children"
                    ][0][field] = value

                with self.assertRaisesRegex(InputError, field):
                    MaintenanceBaseline(tara, self.architecture)

    def test_exact_cpe_resolves_component_and_software(self) -> None:
        change = self.vulnerability(
            affected_components=[],
            affected_cpes=["cpe:2.3:a:bluez:bluez:5.54:*:*:*:*:*:*:*"],
        )

        result = self.evaluate_one(change)

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(
            result["evidence"]["matched_components"][0]["component_id"],
            "COMP-VDCM",
        )
        self.assertEqual(result["evidence"]["matched_software"][0]["name"], "bluez")

    def test_unmatched_vulnerability_is_unresolved(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(
                affected_components=["COMP-UNKNOWN"],
                affected_cpes=["cpe:2.3:a:unknown:unknown:1:*:*:*:*:*:*:*"],
            )
        )

        self.assertEqual(result["decision"], "unresolved")
        self.assertEqual(
            result["evidence"]["unresolved_identifiers"]["components"],
            ["COMP-UNKNOWN"],
        )
        self.assertEqual(result["evidence"]["matched_components"], [])

    def test_known_match_does_not_hide_unknown_identifiers(self) -> None:
        result = self.evaluate_one(
            self.vulnerability(
                affected_components=["COMP-VDCM", "COMP-UNKNOWN"]
            )
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(
            result["evidence"]["unresolved_identifiers"]["components"],
            ["COMP-UNKNOWN"],
        )

    def test_vulnerability_requires_applicability_identifiers(self) -> None:
        change = self.vulnerability(affected_components=[])

        with self.assertRaises(InputError):
            self.evaluate_one(change)

    def test_invalid_cve_identifier_is_rejected(self) -> None:
        with self.assertRaisesRegex(InputError, "valid CVE identifier"):
            self.evaluate_one(self.vulnerability(cve_id="not-a-cve"))

    def test_component_change_reports_changed_top_level_fields(self) -> None:
        result = self.evaluate_one(
            {
                "change_id": "CHANGE-1",
                "type": "component_change",
                "component_id": "COMP-VDCM",
                "before": {"version": "1", "security": {"enabled": False}},
                "after": {"version": "2", "security": {"enabled": True}},
                "source": "unit-test snapshot",
            }
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(
            result["evidence"]["changed_fields"], ["security", "version"]
        )

    def test_component_diff_distinguishes_missing_field_from_null(self) -> None:
        result = self.evaluate_one(
            {
                "change_id": "CHANGE-NULL",
                "type": "component_change",
                "component_id": "COMP-VDCM",
                "before": {},
                "after": {"security_patch": None},
                "source": "unit-test snapshot",
            }
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(result["evidence"]["changed_fields"], ["security_patch"])

    def test_identical_component_states_do_not_require_review(self) -> None:
        result = self.evaluate_one(
            {
                "change_id": "CHANGE-SAME",
                "type": "component_change",
                "component_id": "COMP-VDCM",
                "before": {"version": "1"},
                "after": {"version": "1"},
                "source": "unit-test snapshot",
            }
        )

        self.assertEqual(result["decision"], "no_review")
        self.assertEqual(result["evidence"]["changed_fields"], [])

    def test_change_to_known_component_without_attack_path_still_requires_review(self) -> None:
        result = self.evaluate_one(
            {
                "change_id": "CHANGE-NEW-CHAIN",
                "type": "component_change",
                "component_id": "COMP-EBCM",
                "before": "1.0",
                "after": "2.0",
                "source": "unit-test snapshot",
            }
        )

        self.assertEqual(result["decision"], "review_required")
        self.assertEqual(result["evidence"]["changed_fields"], ["value"])
        self.assertEqual(result["evidence"]["related_attack_steps"], [])

    def test_unknown_component_change_is_unresolved(self) -> None:
        result = self.evaluate_one(
            {
                "change_id": "CHANGE-UNKNOWN",
                "type": "component_change",
                "component_id": "COMP-UNKNOWN",
                "before": {"version": "1"},
                "after": {"version": "2"},
                "source": "unit-test snapshot",
            }
        )

        self.assertEqual(result["decision"], "unresolved")

    def test_duplicate_change_ids_are_rejected(self) -> None:
        with self.assertRaisesRegex(InputError, "Duplicate change_id"):
            self.baseline.evaluate(
                {
                    "changes": [
                        self.vulnerability(),
                        self.vulnerability(cve_id="CVE-2026-0002"),
                    ]
                }
            )

    def test_mismatched_tara_and_architecture_are_rejected(self) -> None:
        architecture = {
            "item_definition": {"item_id": "ITEM-2"},
            "components": [],
        }

        with self.assertRaisesRegex(InputError, "does not match"):
            MaintenanceBaseline(self.tara, architecture)

    def test_empty_change_set_has_zero_counts(self) -> None:
        report = self.baseline.evaluate({"changes": []})

        self.assertEqual(
            report["summary"],
            {
                "total": 0,
                "review_required": 0,
                "no_review": 0,
                "unresolved": 0,
            },
        )
        self.assertEqual(report["recommendations"], [])

    def test_repeated_evaluation_is_deterministic(self) -> None:
        changes = {
            "changes": [
                self.vulnerability("VULN-2", cve_id="CVE-2026-0002"),
                self.vulnerability("VULN-1"),
            ]
        }

        first = evaluate_changes(self.tara, self.architecture, changes)
        second = evaluate_changes(self.tara, self.architecture, changes)

        self.assertEqual(first, second)
        self.assertEqual(
            [item["change_id"] for item in first["recommendations"]],
            ["VULN-2", "VULN-1"],
        )

    def test_shared_reference_artifacts_support_cve_maintenance(self) -> None:
        tara = load_json(TARA_PATH)
        architecture = load_json(ARCHITECTURE_PATH)
        changes = {
            "changes": [
                self.vulnerability(
                    "KNOWN",
                    cve_id="CVE-2020-12351",
                    affected_components=["COMP-VDCM"],
                ),
                self.vulnerability(
                    "NEW",
                    cve_id="CVE-2026-90001",
                    affected_components=[],
                    affected_cpes=[
                        "cpe:2.3:a:eclipse:mosquitto:2.0.10:*:*:*:*:*:*:*"
                    ],
                ),
            ]
        }

        report = evaluate_changes(tara, architecture, changes)

        self.assertEqual(
            [item["decision"] for item in report["recommendations"]],
            ["review_required", "review_required"],
        )
        self.assertEqual(
            report["recommendations"][1]["evidence"]["matched_software"][0]["name"],
            "mosquitto",
        )


if __name__ == "__main__":
    unittest.main()
