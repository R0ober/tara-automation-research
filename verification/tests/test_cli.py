import json
import subprocess
import sys
from pathlib import Path

from tara_verification.injection.__main__ import main

SRC = Path(__file__).resolve().parents[1] / "src"
ARGS = ["--system", "bbw", "--scenarios", "TS-BRK-01", "--operators", "C1a,C1b,C3,C4",
        "--seed", "295"]


def test_cli_writes_dataset(tmp_path, repo):
    out = tmp_path / "v0"
    assert main(["--repo", str(repo), *ARGS, "--out", str(out)]) == 0
    manifest = json.loads((out / "manifest.json").read_text("utf-8"))
    assert manifest["inputs"]["rev"] == "5ed3ae193bf323f9a2a3b467f9d6d67f82e8d3f0"
    assert manifest["counts"]["C1b"] == {"sites": 4, "generated": 4, "skipped": 0,
                                         "rejected": 0, "duplicates": 0, "accepted": 4}
    assert manifest["skipped"] == [] and manifest["duplicates"] == []
    assert manifest["known_violations"] == [["R-REF", "AT-BRK-02-B2", "target_interface"]]
    assert (out / "rejected.jsonl").read_text("utf-8") == ""
    assert manifest["total_cases"] == len(list((out / "dev" / "cases").iterdir()))


def test_cli_refuses_non_empty_out(tmp_path, repo, capsys):
    out = tmp_path / "v0"
    assert main(["--repo", str(repo), *ARGS, "--out", str(out)]) == 0
    assert main(["--repo", str(repo), *ARGS, "--out", str(out)]) == 2
    assert "not empty" in capsys.readouterr().err
    assert main(["--repo", str(repo), *ARGS, "--out", str(out), "--overwrite"]) == 0


def test_cli_wrong_hash_fails(tmp_path, repo, capsys):
    code = main(["--repo", str(repo), *ARGS, "--out", str(tmp_path / "x"),
                 "--expect-sha256", "tara=" + "0" * 64])
    assert code == 2 and "does not match expected" in capsys.readouterr().err


def test_cli_unknown_operator_fails(tmp_path, repo, capsys):
    args = ["--repo", str(repo), "--system", "bbw", "--scenarios", "TS-BRK-01",
            "--operators", "C9", "--seed", "1", "--out", str(tmp_path / "x")]
    assert main(args) == 2 and "unknown operators" in capsys.readouterr().err


def test_module_entry_point(tmp_path, repo):
    r = subprocess.run([sys.executable, "-m", "tara_verification.injection", "--help"],
                       capture_output=True, text=True, env={"PYTHONPATH": str(SRC)}, cwd=repo)
    assert r.returncode == 0 and "--seed" in r.stdout
