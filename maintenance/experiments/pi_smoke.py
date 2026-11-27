"""Run and validate DeepSeek/Pi synthetic and NVD maintenance experiments."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from tara_maintenance.baseline import JsonObject

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_ARGUMENTS = {
    "config_path": "config/maintenance.example.json",
    "changes_path": "examples/changes.json",
    "output_path": "output/example-pi-report.json",
}
EXPECTED_SUMMARY = {
    "total": 4,
    "review_required": 3,
    "no_review": 0,
    "unresolved": 1,
}


@dataclass(frozen=True)
class Scenario:
    prompt: str
    arguments: JsonObject
    expected_summary: JsonObject
    output_directory: Path
    report_path: Path
    synthetic: bool


SCENARIOS = {
    "synthetic": Scenario(
        prompt="/tara-maintenance-example",
        arguments=EXPECTED_ARGUMENTS,
        expected_summary=EXPECTED_SUMMARY,
        output_directory=ROOT / "output" / "pi-example-experiment",
        report_path=ROOT / "output" / "example-pi-report.json",
        synthetic=True,
    ),
    "nvd": Scenario(
        prompt="/tara-maintenance-nvd-example",
        arguments={
            "config_path": "config/maintenance.example.json",
            "changes_path": "experiments/datasets/nvd-bbw/changes.json",
            "output_path": "output/nvd-pi-report.json",
        },
        expected_summary={
            "total": 8,
            "review_required": 5,
            "no_review": 3,
            "unresolved": 0,
        },
        output_directory=ROOT / "output" / "pi-nvd-experiment",
        report_path=ROOT / "output" / "nvd-pi-report.json",
        synthetic=False,
    ),
}


def validate_example_run(events: list[JsonObject], report: JsonObject) -> list[str]:
    """Validate the original synthetic scenario through the generic gate."""

    return validate_run(events, report, SCENARIOS["synthetic"])


def validate_run(
    events: list[JsonObject], report: JsonObject, scenario: Scenario
) -> list[str]:
    """Return consumer-visible failures found in one Pi event stream."""

    errors = []
    starts = [
        event
        for event in events
        if event.get("type") == "tool_execution_start"
        and event.get("toolName") == "tara_maintenance"
    ]
    ends = [
        event
        for event in events
        if event.get("type") == "tool_execution_end"
        and event.get("toolName") == "tara_maintenance"
    ]
    if len(starts) != 1 or len(ends) != 1:
        return [
            f"Expected exactly one complete tool call, got {len(starts)} starts and {len(ends)} ends"
        ]
    if starts[0].get("args") != scenario.arguments:
        errors.append(f"Incorrect tool arguments: {starts[0].get('args')}")
    if ends[0].get("result", {}).get("isError"):
        errors.append("The maintenance tool returned an error")
    if report.get("summary") != scenario.expected_summary:
        errors.append(f"Incorrect report summary: {report.get('summary')}")

    final_text = _final_assistant_text(events)
    if not final_text:
        errors.append("No final assistant response was recorded")
    for recommendation in report.get("recommendations", []):
        change_id = recommendation["change_id"]
        row = next(
            (line for line in final_text.splitlines() if change_id in line),
            "",
        )
        if not row:
            errors.append(f"Final response omitted the row for {change_id}")
            continue
        decision = recommendation["decision"]
        if decision not in row:
            errors.append(f"Final response row for {change_id} omitted decision {decision}")
        subject = recommendation.get("vulnerability_id") or recommendation.get("component_id")
        if subject and subject not in row:
            errors.append(f"Final response row for {change_id} omitted subject {subject}")
        evidence = recommendation.get("evidence", {})
        if (
            not evidence.get("matched_software")
            and "matched by exact CPE" in row
            and decision != "unresolved"
        ):
            errors.append(f"Final response row for {change_id} makes a false CPE matching claim")
    if re.search(r"CVE-\d{4}-\d{4,}\s*\?", final_text, re.IGNORECASE):
        errors.append("Final response contains a questioned CVE identifier")
    report_cpes = {
        item.get("cpe")
        for recommendation in report.get("recommendations", [])
        for field in ("matched_software", "matched_cpe_rules", "excluded_software")
        for item in recommendation.get("evidence", {}).get(field, [])
    }
    for recommendation in report.get("recommendations", []):
        report_cpes.update(
            recommendation.get("evidence", {})
            .get("unresolved_identifiers", {})
            .get("cpes", [])
        )
    for cpe_match in re.findall(r"cpe:2\.3:[^\s`|]+", final_text):
        cpe = cpe_match.rstrip(".,);")
        if cpe not in report_cpes:
            errors.append(f"Final response contains an incomplete or unsupported CPE: {cpe}")
    truncation = ends[0].get("result", {}).get("details", {}).get("truncated")
    if truncation is False and re.search(r"\btruncated\b", final_text, re.IGNORECASE):
        errors.append("Final response makes an unsupported truncation claim")
    return errors


def _final_assistant_text(events: list[JsonObject]) -> str:
    for event in reversed(events):
        if (
            event.get("type") == "message_end"
            and event.get("message", {}).get("role") == "assistant"
            and event.get("message", {}).get("stopReason") == "stop"
        ):
            return "\n".join(
                part.get("text", "")
                for part in event["message"].get("content", [])
                if part.get("type") == "text"
            )
    return ""


def run_experiment(runs: int, scenario_name: str = "synthetic") -> JsonObject:
    """Execute independent Pi sessions and persist only ignored local outputs."""

    scenario = SCENARIOS[scenario_name]
    scenario.output_directory.mkdir(parents=True, exist_ok=True)
    run_results = []
    for run_number in range(1, runs + 1):
        events_path = scenario.output_directory / f"run-{run_number}-events.jsonl"
        response_path = scenario.output_directory / f"run-{run_number}-response.md"
        error_path = scenario.output_directory / f"run-{run_number}-stderr.log"
        with events_path.open("w", encoding="utf-8") as event_stream, error_path.open(
            "w", encoding="utf-8"
        ) as error_stream:
            completed = subprocess.run(
                [
                    str(ROOT / "scripts" / "pi.sh"),
                    "--mode",
                    "json",
                    "--no-session",
                    "--tools",
                    "tara_maintenance",
                    scenario.prompt,
                ],
                cwd=ROOT,
                stdout=event_stream,
                stderr=error_stream,
                text=True,
                check=False,
                timeout=240,
            )
        if completed.returncode:
            raise RuntimeError(
                f"Pi run {run_number} exited {completed.returncode}; see {error_path}"
            )
        events = [
            json.loads(line)
            for line in events_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        report = json.loads(scenario.report_path.read_text(encoding="utf-8"))
        failures = validate_run(events, report, scenario)
        final_text = _final_assistant_text(events)
        response_path.write_text(final_text + "\n", encoding="utf-8")
        run_results.append(
            {
                "run": run_number,
                "passed": not failures,
                "failures": failures,
                "events": str(events_path.relative_to(ROOT)),
                "response": str(response_path.relative_to(ROOT)),
            }
        )

    return {
        "experiment": f"deepseek-pi-{scenario_name}-maintenance",
        "synthetic": scenario.synthetic,
        "runs": runs,
        "passed_runs": sum(item["passed"] for item in run_results),
        "all_passed": all(item["passed"] for item in run_results),
        "results": run_results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="synthetic")
    parser.add_argument("--runs", type=int, default=1, help="Number of independent Pi sessions")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    try:
        summary = run_experiment(args.runs, args.scenario)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"Pi experiment failed: {exc}", file=sys.stderr)
        return 1
    summary_path = SCENARIOS[args.scenario].output_directory / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
