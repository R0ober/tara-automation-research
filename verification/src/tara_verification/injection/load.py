"""Read the injector inputs, verify their hashes, and write canonical JSON."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Development baseline: PR 18, squash-merged into main.
BASELINE_REV = "5ed3ae193bf323f9a2a3b467f9d6d67f82e8d3f0"

# SHA-256 of each input file at BASELINE_REV, keyed by system and role.
BASELINE_SHA256 = {
    "bbw": {
        "tara": "81dc722d35d5f378d0c1c35aac5dfdce7d41ce8213878db27e1b57bbf99efa78",
        "item": "7a32902c5ee9eb21405d3bbabd8b3100bd8cedadac783595e3abc514754a6ed0",
        "spec": "c7d16a6917f582938cc1457f482b3ce985e22722ed7d3b1c709e0dd9dd3dcd76",
    },
    "ota-adas": {
        "tara": "f2995db8d899666f37f1766c02d1e08b4a50dd1d9f540b45b580bcfa0da6a1ca",
        "item": "07ea8be242c1acf5dc1c5ac92d3f71c0627ff6b7333893ef4bb25352bc7039f6",
        "spec": "b1aa6b9df164f5ec9a455364887ca2af9fd6e07508293ddde81cee5cbd8214f6",
    },
}


class InputError(Exception):
    """An input file is missing, unreadable, or has an unexpected hash."""


@dataclass(frozen=True)
class Inputs:
    system: str
    rev: str | None  # None means the working tree
    tara: dict
    item: dict
    spec_text: str
    item_bytes: bytes
    spec_bytes: bytes
    tara_sha256: str
    item_sha256: str
    spec_sha256: str


def input_paths(system: str) -> dict[str, str]:
    """Repository-relative input paths for a system, keyed by role."""
    return {
        "tara": f"shared/reference-tara/{system}/reference-tara.json",
        "item": f"shared/architecture/{system}/item-definition.json",
        "spec": f"shared/architecture/{system}/functional-specification.txt",
    }


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_input(repo: Path, rel_path: str, rev: str | None) -> bytes:
    """Read a file from the working tree, or from a git revision if rev is set."""
    if rev is None:
        path = repo / rel_path
        try:
            return path.read_bytes()
        except OSError as exc:
            raise InputError(f"cannot read {path}: {exc}") from exc
    result = subprocess.run(["git", "-C", str(repo), "show", f"{rev}:{rel_path}"],
                            capture_output=True, check=False)
    if result.returncode != 0:
        raise InputError(f"cannot read {rev}:{rel_path}: "
                         f"{result.stderr.decode('utf-8', 'replace').strip()}")
    return result.stdout


def load_inputs(repo: Path, system: str, rev: str | None = None,
                expected: dict[str, str] | None = None) -> Inputs:
    """Load the TARA, item definition and functional specification of a system.

    If expected is given, it maps a role ("tara", "item", "spec") to a SHA-256,
    and any mismatch raises InputError.
    """
    raw = {role: read_input(repo, path, rev) for role, path in input_paths(system).items()}
    hashes = {role: sha256_bytes(data) for role, data in raw.items()}
    for role, want in (expected or {}).items():
        if role not in hashes:
            raise InputError(f"unknown input role {role!r}")
        if hashes[role] != want:
            raise InputError(f"{input_paths(system)[role]}: SHA-256 {hashes[role]} "
                             f"does not match expected {want}")
    try:
        tara = json.loads(raw["tara"].decode("utf-8"))
        item = json.loads(raw["item"].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"invalid JSON input for {system}: {exc}") from exc
    return Inputs(
        system=system,
        rev=rev,
        tara=tara,
        item=item,
        spec_text=raw["spec"].decode("utf-8"),
        item_bytes=raw["item"],
        spec_bytes=raw["spec"],
        tara_sha256=hashes["tara"],
        item_sha256=hashes["item"],
        spec_sha256=hashes["spec"],
    )


def canonical(doc: dict) -> str:
    # Single writer for baseline and every case, so layout never reveals edits.
    # Keys are NOT sorted; original order is preserved.
    return json.dumps(doc, ensure_ascii=False, indent=2) + "\n"
