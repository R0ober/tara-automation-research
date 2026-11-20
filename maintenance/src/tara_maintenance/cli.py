"""Command-line interface for the TARA maintenance baseline."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .baseline import InputError, evaluate_changes, load_json
from .config import (
    PROJECT_ROOT,
    find_config_path,
    load_config,
    resolve_path,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tara-maintenance",
        description="Decide whether vulnerability or component changes require TARA review.",
    )
    parser.add_argument(
        "--config",
        help="Configuration JSON; defaults to TARA_MAINTENANCE_CONFIG or config/maintenance.json",
    )
    parser.add_argument("--tara", help="Existing TARA JSON file; overrides the config")
    parser.add_argument(
        "--architecture", help="Reference item architecture JSON file; overrides the config"
    )
    parser.add_argument("--changes", help="Change-event JSON file; overrides the config")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", help="Write the report to this file; overrides the config")
    output.add_argument(
        "--stdout", action="store_true", help="Write to standard output, ignoring output_path"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config_path = find_config_path(args.config)
        config = load_config(config_path) if config_path else {}
        tara_path = _resolve_setting(args.tara, config.get("tara_path"))
        architecture_path = _resolve_setting(
            args.architecture, config.get("architecture_path")
        )
        changes_path = _resolve_setting(args.changes, config.get("changes_path"))
        missing = [
            name
            for name, value in (
                ("--tara", tara_path),
                ("--architecture", architecture_path),
                ("--changes", changes_path),
            )
            if value is None
        ]
        if missing:
            raise InputError(
                f"Missing {', '.join(missing)}. Pass the option or configure the "
                "corresponding path in config/maintenance.json."
            )

        report = evaluate_changes(
            load_json(tara_path),
            load_json(architecture_path),
            load_json(changes_path),
        )
        rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        output_path = _resolve_setting(args.output, config.get("output_path"))
        if not args.stdout and output_path and str(output_path) != "-":
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
    except (InputError, OSError, UnicodeError) as exc:
        print(f"tara-maintenance: {exc}", file=sys.stderr)
        return 2
    return 0


def _resolve_setting(cli_value: str | None, config_value: str | None) -> Path | None:
    if cli_value:
        if cli_value == "-":
            return Path("-")
        return resolve_path(cli_value, Path.cwd())
    if config_value:
        return resolve_path(config_value, PROJECT_ROOT)
    return None


def entrypoint() -> None:
    raise SystemExit(main())


if __name__ == "__main__":
    entrypoint()
