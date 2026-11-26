from __future__ import annotations

import unittest
from pathlib import Path

from tara_maintenance import InputError, load_json
from tara_maintenance.baseline import JsonObject
from tara_maintenance.evaluate import evaluate_dataset

MAINTENANCE_DIR = Path(__file__).resolve().parents[1]
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


class EvaluationTests(unittest.TestCase):
    tara: JsonObject
    architecture: JsonObject
    def setUp(self) -> None:
        self.tara = {
            "tara_metadata": {"item_id": "ITEM-1"},
            "threat_scenarios_and_attack_trees": [],
        }
        self.architecture = {
            "item_definition": {"item_id": "ITEM-1"},
            "components": [{"component_id": "COMP-1", "name": "Controller"}],
        }

    @staticmethod
    def case(expected: str, change_id: str) -> JsonObject:
        return {
            "expected_decision": expected,
            "expected_components": ["COMP-1"] if expected != "unresolved" else [],
            "change": {
                "change_id": change_id,
                "type": "vulnerability",
                "cve_id": "CVE-2026-0001",
                "affected_components": ["COMP-1"] if expected != "unresolved" else ["UNKNOWN"],
                "source": "evaluation test",
            },
        }

    def test_unresolved_is_separate_from_recall_and_false_positive_rate(self) -> None:
        dataset = {
            "dataset_id": "metrics-test",
            "cases": [
                self.case("review_required", "TP"),
                self.case("no_review", "FP"),
                self.case("unresolved", "UNRESOLVED"),
            ],
        }
        # Existing-CVE suppression makes the expected review case a false negative.
        self.tara["threat_scenarios_and_attack_trees"] = [
            {
                "threat_scenario_id": "TS-1",
                "attack_tree": {
                    "node_id": "LEAF-1",
                    "target_component": "COMP-1",
                    "vulnerability_reference": "CVE-2026-0001",
                },
            }
        ]

        result = evaluate_dataset(self.tara, self.architecture, dataset)
        summary = result["summary"]

        self.assertEqual(summary["false_negative"], 1)
        self.assertEqual(summary["false_positive"], 0)
        self.assertEqual(summary["detection_recall"], 0)
        self.assertEqual(summary["false_positive_rate"], 0)
        self.assertEqual(summary["unresolved"], 1)

    def test_shared_synthetic_dataset_meets_all_rule_labels(self) -> None:
        dataset = load_json(
            MAINTENANCE_DIR / "experiments" / "datasets" / "synthetic-maintenance.json"
        )
        tara = load_json(TARA_PATH)
        architecture = load_json(ARCHITECTURE_PATH)

        result = evaluate_dataset(tara, architecture, dataset)

        self.assertEqual(result["summary"]["total"], 12)
        self.assertEqual(result["summary"]["decision_accuracy"], 1.0)
        self.assertEqual(result["summary"]["detection_recall"], 1.0)
        self.assertEqual(result["summary"]["false_positive_rate"], 0.0)
        self.assertEqual(result["summary"]["evidence_support_rate"], 1.0)
        self.assertEqual(result["summary"]["unresolved"], 2)

    def test_external_changes_reject_duplicate_ids_before_indexing(self) -> None:
        case = self.case("review_required", "DUPLICATE")
        labels = {"cases": [{"change_id": "DUPLICATE", "expected_decision": "review_required"}]}

        with self.assertRaises(InputError):
            evaluate_dataset(
                self.tara,
                self.architecture,
                labels,
                {"changes": [case["change"], case["change"]]},
            )


if __name__ == "__main__":
    unittest.main()
