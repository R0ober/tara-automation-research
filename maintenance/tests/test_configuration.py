from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MAINTENANCE_DIR = Path(__file__).resolve().parents[1]


class ConfigurationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tara = {
            "tara_metadata": {
                "document_id": "TARA-CONFIG",
                "version": "1",
                "item_id": "ITEM-CONFIG",
            },
            "threat_scenarios_and_attack_trees": [],
        }
        self.architecture = {
            "item_definition": {"item_id": "ITEM-CONFIG"},
            "components": [{"component_id": "COMP-1", "name": "Controller"}],
        }
        self.one_change = {
            "changes": [
                {
                    "change_id": "VULN-CONFIG",
                    "type": "vulnerability",
                    "cve_id": "CVE-2026-0001",
                    "affected_components": ["COMP-1"],
                    "source": "configuration unit test",
                }
            ]
        }

    def write_fixtures(self, directory: Path, changes: dict) -> dict[str, Path]:
        paths = {
            "tara": directory / "tara.json",
            "architecture": directory / "architecture.json",
            "changes": directory / "changes.json",
        }
        documents = {
            "tara": self.tara,
            "architecture": self.architecture,
            "changes": changes,
        }
        for name, path in paths.items():
            path.write_text(json.dumps(documents[name]), encoding="utf-8")
        return paths

    @staticmethod
    def write_config(directory: Path, paths: dict[str, Path], output: Path) -> Path:
        config_path = directory / "maintenance.json"
        config_path.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "tara_path": str(paths["tara"]),
                    "architecture_path": str(paths["architecture"]),
                    "changes_path": str(paths["changes"]),
                    "output_path": str(output),
                }
            ),
            encoding="utf-8",
        )
        return config_path

    @staticmethod
    def run_cli(
        arguments: list[str],
        config_path: Path | None = None,
        cwd: Path = MAINTENANCE_DIR,
    ) -> subprocess.CompletedProcess:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(MAINTENANCE_DIR / "src")
        environment.pop("TARA_MAINTENANCE_CONFIG", None)
        if config_path:
            environment["TARA_MAINTENANCE_CONFIG"] = str(config_path)
        return subprocess.run(
            [sys.executable, "-m", "tara_maintenance", *arguments],
            cwd=cwd,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_config_file_supplies_all_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = self.write_fixtures(directory, self.one_change)
            config = self.write_config(directory, paths, directory / "report.json")

            completed = self.run_cli(["--config", str(config), "--stdout"])

            self.assertEqual(completed.returncode, 0, completed.stderr)
            report = json.loads(completed.stdout)
            self.assertEqual(report["summary"]["review_required"], 1)

    def test_cli_changes_and_output_override_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            configured_paths = self.write_fixtures(directory, {"changes": []})
            override_changes = directory / "override-changes.json"
            override_changes.write_text(json.dumps(self.one_change), encoding="utf-8")
            configured_output = directory / "configured-report.json"
            override_output = directory / "nested" / "override-report.json"
            config = self.write_config(directory, configured_paths, configured_output)

            completed = self.run_cli(
                [
                    "--config",
                    str(config),
                    "--changes",
                    str(override_changes),
                    "--output",
                    str(override_output),
                ]
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertFalse(configured_output.exists())
            report = json.loads(override_output.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["total"], 1)

    def test_environment_variable_selects_config(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = self.write_fixtures(directory, self.one_change)
            config = self.write_config(directory, paths, directory / "report.json")

            completed = self.run_cli(["--stdout"], config_path=config)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["summary"]["total"], 1)

    def test_invalid_config_returns_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "maintenance.json"
            config.write_text('{"schema_version": "2.0"}', encoding="utf-8")

            completed = self.run_cli(["--config", str(config), "--stdout"])

            self.assertEqual(completed.returncode, 2)
            self.assertIn("schema_version '1.0'", completed.stderr)
            self.assertEqual(completed.stdout, "")

    def test_unknown_config_key_returns_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = self.write_fixtures(directory, self.one_change)
            output = directory / "report.json"
            config = self.write_config(directory, paths, output)
            document = json.loads(config.read_text(encoding="utf-8"))
            document["output_paht"] = document.pop("output_path")
            config.write_text(json.dumps(document), encoding="utf-8")

            completed = self.run_cli(["--config", str(config)])

            self.assertEqual(completed.returncode, 2)
            self.assertIn("unknown keys: output_paht", completed.stderr)
            self.assertEqual(completed.stdout, "")
            self.assertFalse(output.exists())

    def test_config_output_dash_writes_standard_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            paths = self.write_fixtures(directory, self.one_change)
            config = self.write_config(directory, paths, Path("-"))

            completed = self.run_cli(["--config", str(config)], cwd=directory)

            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["summary"]["total"], 1)
            self.assertFalse((directory / "-").exists())

    def test_tracked_example_config_runs_explicit_example_data(self) -> None:
        completed = self.run_cli(
            [
                "--config",
                "config/maintenance.example.json",
                "--changes",
                "examples/changes.json",
                "--stdout",
            ]
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout)["summary"]["total"], 4)


if __name__ == "__main__":
    unittest.main()
