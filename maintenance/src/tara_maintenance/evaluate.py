"""Evaluation of maintenance decisions against labeled synthetic datasets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from .baseline import InputError, evaluate_changes, load_json
from .config import PROJECT_ROOT, find_config_path, load_config, resolve_path

DECISIONS = {"review_required", "no_review", "unresolved"}


def evaluate_dataset(
    tara: dict[str, Any], architecture: dict[str, Any], dataset: dict[str, Any]
) -> dict[str, Any]:
    """Evaluate decision and structural-evidence metrics for a labeled dataset."""

    cases = dataset.get("cases")
    if not isinstance(cases, list) or not cases:
        raise InputError("Evaluation dataset requires a non-empty 'cases' array")
    changes = []
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or not isinstance(case.get("change"), dict):
            raise InputError(f"Evaluation case {index} requires a change object")
        if case.get("expected_decision") not in DECISIONS:
            raise InputError(f"Evaluation case {index} has an invalid expected_decision")
        changes.append(case["change"])

    report = evaluate_changes(tara, architecture, {"changes": changes})
    predictions = {item["change_id"]: item for item in report["recommendations"]}
    results = []
    for case in cases:
        change_id = case["change"]["change_id"]
        prediction = predictions[change_id]
        expected = case["expected_decision"]
        actual = prediction["decision"]
        evidence_supported = _evidence_is_supported(
            prediction, case.get("expected_components", [])
        )
        results.append(
            {
                "change_id": change_id,
                "expected_decision": expected,
                "actual_decision": actual,
                "correct": actual == expected,
                "evidence_supported": evidence_supported,
            }
        )

    true_positive = _count(results, "review_required", "review_required")
    false_negative = _count(results, "review_required", "no_review")
    false_positive = _count(results, "no_review", "review_required")
    true_negative = _count(results, "no_review", "no_review")
    unresolved = sum(item["actual_decision"] == "unresolved" for item in results)
    correct = sum(item["correct"] for item in results)
    evidence_supported = sum(item["evidence_supported"] for item in results)
    return {
        "dataset_id": dataset.get("dataset_id"),
        "synthetic": dataset.get("synthetic") is True,
        "summary": {
            "total": len(results),
            "correct": correct,
            "decision_accuracy": correct / len(results),
            "detection_recall": _ratio(true_positive, true_positive + false_negative),
            "false_positive_rate": _ratio(false_positive, false_positive + true_negative),
            "evidence_support_rate": evidence_supported / len(results),
            "unresolved": unresolved,
            "true_positive": true_positive,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "true_negative": true_negative,
        },
        "cases": results,
    }


def _count(results: list[dict[str, Any]], expected: str, actual: str) -> int:
    return sum(
        item["expected_decision"] == expected and item["actual_decision"] == actual
        for item in results
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _evidence_is_supported(
    prediction: dict[str, Any], expected_components: Any
) -> bool:
    if not isinstance(expected_components, list):
        return False
    evidence = prediction.get("evidence", {})
    if not evidence.get("source", {}).get("name"):
        return False

    change_type = prediction["change_type"]
    decision = prediction["decision"]
    if change_type == "vulnerability":
        matched = {
            item["component_id"] for item in evidence.get("matched_components", [])
        }
        unresolved = evidence.get("unresolved_identifiers", {})
        unknown_components = set(unresolved.get("components", []))
        known_expected = set(expected_components) - unknown_components
        if matched != known_expected:
            return False
        if decision == "review_required":
            return bool(matched)
        if decision == "no_review":
            return bool(evidence.get("existing_vulnerability_references"))
        return not matched and bool(unresolved.get("components") or unresolved.get("cpes"))

    if set(expected_components) - {prediction["component_id"]}:
        return False
    if decision == "review_required":
        return bool(evidence.get("changed_fields")) and evidence.get("before") != evidence.get(
            "after"
        )
    if decision == "no_review":
        return evidence.get("before") == evidence.get("after")
    return not evidence.get("related_attack_steps")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tara-maintenance-evaluate")
    parser.add_argument("--config", help="Maintenance configuration JSON")
    parser.add_argument("--dataset", required=True, help="Labeled evaluation dataset JSON")
    parser.add_argument("--output", help="Write metrics JSON instead of using standard output")
    args = parser.parse_args(argv)
    try:
        config_path = find_config_path(args.config)
        if not config_path:
            raise InputError("Evaluation requires --config or config/maintenance.json")
        config = load_config(config_path)
        tara_path = resolve_path(config["tara_path"], PROJECT_ROOT)
        architecture_path = resolve_path(config["architecture_path"], PROJECT_ROOT)
        dataset_path = resolve_path(args.dataset, Path.cwd())
        result = evaluate_dataset(
            load_json(tara_path), load_json(architecture_path), load_json(dataset_path)
        )
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            output_path = resolve_path(args.output, Path.cwd())
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (InputError, KeyError, OSError, UnicodeError) as exc:
        print(f"tara-maintenance-evaluate: {exc}", file=sys.stderr)
        return 2
    return 0


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
