from __future__ import annotations

import copy
import unittest
from pathlib import Path

from tara_maintenance import InputError, load_json
from tara_maintenance.baseline import JsonObject
from tara_maintenance.review import build_reviewed_tara


class ReviewedTaraTests(unittest.TestCase):
    tara: JsonObject
    report: JsonObject

    def setUp(self) -> None:
        self.tara = {
            "tara_metadata": {
                "document_id": "TARA-1",
                "version": "1.0.0",
                "item_id": "ITEM-1",
            },
            "threat_scenarios_and_attack_trees": [
                {"threat_scenario_id": "TS-1", "attack_tree": {"node_id": "ROOT-1"}}
            ],
        }
        self.report = {
            "tara": {"document_id": "TARA-1", "version": "1.0.0", "item_id": "ITEM-1"},
            "summary": {
                "total": 1,
                "review_required": 1,
                "no_review": 0,
                "unresolved": 0,
            },
            "recommendations": [
                {"change_id": "CHANGE-1", "decision": "review_required", "evidence": {}}
            ],
        }

    def test_overlay_preserves_original_tara_and_report(self) -> None:
        original = copy.deepcopy(self.tara)

        reviewed = build_reviewed_tara(self.tara, self.report)

        self.assertEqual(self.tara, original)
        self.assertEqual(
            reviewed["threat_scenarios_and_attack_trees"],
            original["threat_scenarios_and_attack_trees"],
        )
        self.assertEqual(reviewed["maintenance_review"]["summary"], self.report["summary"])
        self.assertEqual(
            reviewed["maintenance_review"]["recommendations"],
            self.report["recommendations"],
        )
        restored = copy.deepcopy(reviewed)
        del restored["maintenance_review"]
        self.assertEqual(restored, original)

    def test_overlay_does_not_alias_report_mutable_data(self) -> None:
        reviewed = build_reviewed_tara(self.tara, self.report)

        self.report["recommendations"][0]["decision"] = "no_review"

        self.assertEqual(
            reviewed["maintenance_review"]["recommendations"][0]["decision"],
            "review_required",
        )

    def test_mismatched_report_is_rejected(self) -> None:
        self.report["tara"]["item_id"] = "ITEM-2"

        with self.assertRaises(InputError):
            build_reviewed_tara(self.tara, self.report)

    def test_existing_overlay_is_not_stacked(self) -> None:
        self.tara["maintenance_review"] = {"schema_version": "1.0"}

        with self.assertRaises(InputError):
            build_reviewed_tara(self.tara, self.report)

    def test_real_reference_tara_round_trip(self) -> None:
        reference = (
            Path(__file__).resolve().parents[2]
            / "shared"
            / "reference-tara"
            / "bbw"
            / "reference-tara.json"
        )
        original = load_json(reference)
        metadata = original["tara_metadata"]
        report = {
            "tara": {
                "document_id": metadata["document_id"],
                "version": metadata["version"],
                "item_id": metadata["item_id"],
            },
            "summary": {
                "total": 0,
                "review_required": 0,
                "no_review": 0,
                "unresolved": 0,
            },
            "recommendations": [],
        }

        reviewed = build_reviewed_tara(original, report)
        del reviewed["maintenance_review"]

        self.assertEqual(reviewed, original)


if __name__ == "__main__":
    unittest.main()
