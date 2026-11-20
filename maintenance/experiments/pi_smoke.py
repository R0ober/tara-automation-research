"""Run and validate the DeepSeek/Pi synthetic maintenance smoke experiment."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = ROOT / "output" / "pi-example-experiment"
REPORT_PATH = ROOT / "output" / "example-pi-report.json"
EXPECTED_ARGUMENTS = {
    "config_path": "config/maintenance.example.json",
    "changes_path": "examples/changes.json",
    "output_path": "output/example-pi-report.json",
}
EXPECTED_SUMMARY = {
    "total": 4,
    "review_required": 2,
    "no_review": 1,
    "unresolved": 1,
}


def validate_example_run(events: list[dict[str, Any]], report: dict[str, Any]) -> list[str]:
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
        return [f"Expected exactly one complete tool call, got {len(starts)} starts and {len(ends)} ends"]
    if starts[0].get("args") != EXPECTED_ARGUMENTS:
        errors.append(f"Incorrect tool arguments: {starts[0].get('args')}")
    if ends[0].get("result", {}).get("isError"):
        errors.append("The maintenance tool returned an error")
    if report.get("summary") != EXPECTED_SUMMARY:
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
        for field in ("decision",):
            value = recommendation[field]
            if value not in row:
                errors.append(f"Final response row for {change_id} omitted {field} {value}")
        subject = recommendation.get("vulnerability_id") or recommendation.get("component_id")
        if subject and subject not in row:
            errors.append(f"Final response row for {change_id} omitted subject {subject}")
        evidence = recommendation.get("evidence", {})
        if (
            not evidence.get("matched_software")
            and "matched by exact CPE" in row
            and recommendation["decision"] != "unresolved"
        ):
            errors.append(f"Final response row for {change_id} makes a false CPE matching claim")
    if re.search(r"CVE-\d{4}-\d{4,}\s*\?", final_text, re.IGNORECASE):
        errors.append("Final response contains a questioned CVE identifier")
    report_cpes = {
        software.get("cpe")
        for recommendation in report.get("recommendations", [])
        for software in recommendation.get("evidence", {}).get("matched_software", [])
    }
    for cpe in re.findall(r"cpe:2\.3:[^\s`|]+", final_text):
        if cpe not in report_cpes:
            errors.append(f"Final response contains an incomplete or unsupported CPE: {cpe}")
    truncation = ends[0].get("result", {}).get("details", {}).get("truncated")
    if truncation is False and re.search(r"\btruncated\b", final_text, re.IGNORECASE):
        errors.append("Final response makes an unsupported truncation claim")
    return errors


def _final_assistant_text(events: list[dict[str, Any]]) -> str:
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


def run_experiment(runs: int) -> dict[str, Any]:
    """Execute independent Pi sessions and persist only ignored local outputs."""

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    run_results = []
    for run_number in range(1, runs + 1):
        events_path = OUTPUT_DIRECTORY / f"run-{run_number}-events.jsonl"
        response_path = OUTPUT_DIRECTORY / f"run-{run_number}-response.md"
        error_path = OUTPUT_DIRECTORY / f"run-{run_number}-stderr.log"
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
                    "/tara-maintenance-example",
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
        report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
        failures = validate_example_run(events, report)
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
        "experiment": "deepseek-pi-synthetic-maintenance",
        "synthetic": True,
        "runs": runs,
        "passed_runs": sum(item["passed"] for item in run_results),
        "all_passed": all(item["passed"] for item in run_results),
        "results": run_results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=1, help="Number of independent Pi sessions")
    args = parser.parse_args(argv)
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    try:
        summary = run_experiment(args.runs)
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(f"Pi experiment failed: {exc}", file=sys.stderr)
        return 1
    summary_path = OUTPUT_DIRECTORY / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
