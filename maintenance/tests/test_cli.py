from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MAINTENANCE_DIR = Path(__file__).resolve().parents[1]


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tara = {
            "tara_metadata": {
                "document_id": "TARA-CLI",
                "version": "1",
                "item_id": "ITEM-CLI",
            },
            "threat_scenarios_and_attack_trees": [],
        }
        self.architecture = {
            "item_definition": {"item_id": "ITEM-CLI"},
            "components": [{"component_id": "COMP-1", "name": "Controller"}],
        }
        self.changes = {
            "changes": [
                {
                    "change_id": "VULN-CLI",
                    "type": "vulnerability",
                    "cve_id": "CVE-2026-0001",
                    "affected_components": ["COMP-1"],
                    "source": "CLI unit test",
                }
            ]
        }

    def run_cli(
        self, input_dir: Path, output: Path, tara_output: Path | None = None
    ) -> subprocess.CompletedProcess:
        paths = {
            "tara": self.tara,
            "architecture": self.architecture,
            "changes": self.changes,
        }
        for name, document in paths.items():
            (input_dir / f"{name}.json").write_text(
                json.dumps(document), encoding="utf-8"
            )
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(MAINTENANCE_DIR / "src")
        command = [
            sys.executable,
            "-m",
            "tara_maintenance",
            "--tara",
            str(input_dir / "tara.json"),
            "--architecture",
            str(input_dir / "architecture.json"),
            "--changes",
            str(input_dir / "changes.json"),
            "--output",
            str(output),
        ]
        if tara_output:
            command.extend(("--tara-output", str(tara_output)))
        return subprocess.run(
            command,
            cwd=MAINTENANCE_DIR,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_cli_writes_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_dir = Path(temporary_directory)
            output = input_dir / "report.json"

            completed = self.run_cli(input_dir, output)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["recommendations"][0]["decision"], "review_required")
            self.assertEqual(report["summary"]["review_required"], 1)

    def test_cli_refuses_to_overwrite_input_tara(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_dir = Path(temporary_directory)
            tara_path = input_dir / "tara.json"
            output = input_dir / "report.json"

            completed = self.run_cli(input_dir, output, tara_output=tara_path)

            self.assertEqual(completed.returncode, 2)
            self.assertIn("must not overwrite", completed.stderr)
            self.assertEqual(json.loads(tara_path.read_text(encoding="utf-8")), self.tara)

    def test_cli_reports_invalid_json_and_does_not_create_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_dir = Path(temporary_directory)
            output = input_dir / "report.json"
            for name, document in (
                ("tara", self.tara),
                ("architecture", self.architecture),
            ):
                (input_dir / f"{name}.json").write_text(
                    json.dumps(document), encoding="utf-8"
                )
            (input_dir / "changes.json").write_text("{", encoding="utf-8")
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(MAINTENANCE_DIR / "src")

            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tara_maintenance",
                    "--tara",
                    str(input_dir / "tara.json"),
                    "--architecture",
                    str(input_dir / "architecture.json"),
                    "--changes",
                    str(input_dir / "changes.json"),
                    "--output",
                    str(output),
                ],
                cwd=MAINTENANCE_DIR,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 2)
            self.assertIn("Cannot load JSON", completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
