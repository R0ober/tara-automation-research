from __future__ import annotations

import unittest
from pathlib import Path

from tara_maintenance import InputError, evaluate_changes, load_json
from tara_maintenance.baseline import JsonObject
from tara_maintenance.evaluate import evaluate_dataset
from tara_maintenance.nvd import nvd_to_changes

MAINTENANCE_DIR = Path(__file__).resolve().parents[1]
NVD_DIR = MAINTENANCE_DIR / "experiments" / "datasets" / "nvd-bbw"
TARA_PATH = (
    MAINTENANCE_DIR.parent
    / "shared"
    / "reference-tara"
    / "bbw"
    / "reference-tara.json"
)
ARCHITECTURE_PATH = (
    MAINTENANCE_DIR.parent / "shared" / "architecture" / "bbw" / "item-definition.json"
)
CVE_IDS = (
    "CVE-2020-12351",
    "CVE-2022-0847",
    "CVE-2021-34434",
    "CVE-2020-22284",
    "CVE-2014-4883",
    "CVE-2020-22283",
    "CVE-2024-3935",
    "CVE-2024-10525",
)


class NvdIntegrationTests(unittest.TestCase):
    tara: JsonObject
    architecture: JsonObject
    changes: list[JsonObject]

    def setUp(self) -> None:
        self.tara = load_json(TARA_PATH)
        self.architecture = load_json(ARCHITECTURE_PATH)
        self.changes = [
            change
            for cve_id in CVE_IDS
            for change in nvd_to_changes(load_json(NVD_DIR / f"{cve_id}.json"))
        ]

    def test_real_nvd_snapshots_drive_version_aware_decisions(self) -> None:
        report = evaluate_changes(self.tara, self.architecture, {"changes": self.changes})
        decisions = {
            item["vulnerability_id"]: item["decision"]
            for item in report["recommendations"]
        }

        self.assertEqual(
            decisions,
            {
                "CVE-2020-12351": "no_review",
                "CVE-2022-0847": "review_required",
                "CVE-2021-34434": "review_required",
                "CVE-2020-22284": "review_required",
                "CVE-2014-4883": "no_review",
                "CVE-2020-22283": "no_review",
                "CVE-2024-3935": "review_required",
                "CVE-2024-10525": "review_required",
            },
        )
        self.assertEqual(
            report["summary"],
            {"total": 8, "review_required": 5, "no_review": 3, "unresolved": 0},
        )

    def test_range_evidence_contains_nvd_match_criteria(self) -> None:
        report = evaluate_changes(self.tara, self.architecture, {"changes": self.changes})
        recommendations = {
            item["vulnerability_id"]: item for item in report["recommendations"]
        }

        dirty_pipe = recommendations["CVE-2022-0847"]["evidence"]["matched_cpe_rules"][0]
        mosquitto = recommendations["CVE-2021-34434"]["evidence"]["matched_cpe_rules"][0]
        excluded = recommendations["CVE-2020-12351"]
        self.assertEqual(dirty_pipe["match_criteria_id"], "22317905-77D0-46F0-A4F8-06B630002681")
        self.assertEqual(dirty_pipe["installed_version"], "5.10.70")
        self.assertEqual(mosquitto["match_criteria_id"], "07853BAC-AF86-4FF4-B0DB-FC0B91EE1E28")
        self.assertEqual(mosquitto["installed_version"], "2.0.10")
        self.assertTrue(excluded["evidence"]["excluded_software"])
        self.assertFalse(excluded["evidence"].get("existing_vulnerability_references"))
        self.assertEqual(
            recommendations["CVE-2022-0847"]["evidence"]["source"]["last_modified"],
            "2026-06-17T04:21:21.750",
        )
        self.assertEqual(
            recommendations["CVE-2022-0847"]["evidence"]["cisa"]["exploit_added"],
            "2022-04-25",
        )

    def test_nvd_adapter_preserves_description_status_and_cisa_evidence(self) -> None:
        dirty_pipe = next(
            change for change in self.changes if change["cve_id"] == "CVE-2022-0847"
        )

        self.assertIn("copy_page_to_iter_pipe", dirty_pipe["summary"])
        self.assertEqual(dirty_pipe["vulnerability_status"], "Analyzed")
        self.assertEqual(dirty_pipe["cisa"]["exploit_added"], "2022-04-25")
        self.assertTrue(dirty_pipe["affected_cpe_ranges"])

    def test_new_vulnerability_with_unaffected_version_does_not_require_review(self) -> None:
        change = {
            "change_id": "UNAFFECTED",
            "type": "vulnerability",
            "cve_id": "CVE-2026-99999",
            "affected_cpes": ["cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*"],
            "affected_cpe_ranges": [
                {
                    "cpe": "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*",
                    "version_start_including": "2.0.11",
                    "version_end_including": "2.0.12",
                }
            ],
            "source": "range regression test",
        }

        report = evaluate_changes(self.tara, self.architecture, {"changes": [change]})
        recommendation = report["recommendations"][0]

        self.assertEqual(recommendation["decision"], "no_review")
        self.assertTrue(recommendation["evidence"]["excluded_software"])

    def test_manual_nvd_labels_are_evaluated_from_external_changes(self) -> None:
        labels = load_json(NVD_DIR / "labels.json")

        result = evaluate_dataset(
            self.tara,
            self.architecture,
            labels,
            {"changes": self.changes},
        )

        self.assertFalse(result["synthetic"])
        self.assertEqual(result["summary"]["decision_accuracy"], 1.0)
        self.assertEqual(result["summary"]["detection_recall"], 1.0)
        self.assertEqual(result["summary"]["false_positive_rate"], 0.0)
        self.assertEqual(result["summary"]["unresolved"], 0)

    def test_range_only_input_is_evaluated_without_duplicate_cpe_list(self) -> None:
        rule = {
            "cpe": "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*",
            "version_start_including": "2.0.0",
            "version_end_including": "2.0.11",
        }
        change = {
            "change_id": "RANGE-ONLY",
            "type": "vulnerability",
            "cve_id": "CVE-2026-99998",
            "affected_cpe_ranges": [rule],
            "source": "audit regression test",
        }

        report = evaluate_changes(self.tara, self.architecture, {"changes": [change]})

        self.assertEqual(report["recommendations"][0]["decision"], "review_required")

    def test_unknown_component_blocks_unaffected_version_no_review(self) -> None:
        rule = {
            "cpe": "cpe:2.3:a:eclipse:mosquitto:*:*:*:*:*:*:*:*",
            "version_end_including": "2.0.9",
        }
        change = {
            "change_id": "UNKNOWN-AND-EXCLUDED",
            "type": "vulnerability",
            "cve_id": "CVE-2026-99997",
            "affected_components": ["COMP-UNKNOWN"],
            "affected_cpe_ranges": [rule],
            "source": "audit regression test",
        }

        report = evaluate_changes(self.tara, self.architecture, {"changes": [change]})

        self.assertEqual(report["recommendations"][0]["decision"], "unresolved")


    def test_nvd_record_without_cpe_is_unresolved_not_invalid(self) -> None:
        document = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-99996",
                        "vulnStatus": "Awaiting Analysis",
                        "descriptions": [],
                    }
                }
            ]
        }
        changes = nvd_to_changes(document)

        report = evaluate_changes(self.tara, self.architecture, {"changes": changes})

        self.assertTrue(changes[0]["applicability_unknown"])
        self.assertEqual(report["recommendations"][0]["decision"], "unresolved")
        evaluation = evaluate_dataset(
            self.tara,
            self.architecture,
            {
                "cases": [
                    {
                        "expected_decision": "unresolved",
                        "expected_components": [],
                        "change": changes[0],
                    }
                ]
            },
        )
        self.assertEqual(evaluation["summary"]["evidence_support_rate"], 1.0)

    def test_malformed_nvd_vulnerability_is_an_input_error(self) -> None:
        with self.assertRaises(InputError):
            nvd_to_changes({"vulnerabilities": [42]})

    def test_explicit_unknown_blocks_exclusion_no_review(self) -> None:
        rule = {
            "cpe": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
            "version_end_excluding": "5.10.60",
        }
        change = {
            "change_id": "FLAG-AND-EXCLUDED",
            "type": "vulnerability",
            "cve_id": "CVE-2026-99995",
            "affected_cpe_ranges": [rule],
            "applicability_unknown": True,
            "source": "audit regression test",
        }

        report = evaluate_changes(self.tara, self.architecture, {"changes": [change]})

        self.assertEqual(report["recommendations"][0]["decision"], "unresolved")

if __name__ == "__main__":
    unittest.main()
