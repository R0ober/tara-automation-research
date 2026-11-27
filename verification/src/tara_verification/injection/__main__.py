"""Command line: python -m tara_verification.injection --system bbw ..."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .. import __version__
from .known_issues import KNOWN_ISSUES, KNOWN_VIOLATIONS
from .load import BASELINE_REV, BASELINE_SHA256, InputError, input_paths, load_inputs
from .operators import Skip, apply, make_context
from .sites import OPERATORS, enumerate_sites
from .validate import check_case
from .write import (
    DatasetError, assign_case_ids, prepare_out, rejected_from_skip, rejected_from_validation,
    write_dataset,
)

COUNT_KEYS = ("sites", "generated", "skipped", "rejected", "duplicates", "accepted")


def run(*, repo: Path, system: str, scenarios: list[str], operators: list[str], seed: int,
        out: Path, rev: str | None = BASELINE_REV, split: str = "dev", overwrite: bool = False,
        expected_sha256: dict[str, str] | None = None) -> dict:
    """Generate, validate and write one dataset. Return the manifest."""
    if expected_sha256 is None and rev == BASELINE_REV:
        expected_sha256 = BASELINE_SHA256.get(system)
    inputs = load_inputs(repo, system, rev=rev, expected=expected_sha256)
    ctx = make_context(inputs.tara, inputs.item)
    sites = enumerate_sites(inputs.tara, scenarios, operators)

    counts = {op: dict.fromkeys(COUNT_KEYS, 0) for op in operators}
    candidates, rejected, skipped = [], [], []
    for site in sites:
        c = counts[site.operator]
        c["sites"] += 1
        result = apply(ctx, site, seed)
        if isinstance(result, Skip):
            c["skipped"] += 1
            skipped.append(rejected_from_skip(result))
            continue
        c["generated"] += 1
        problems = check_case(inputs.tara, result.mutant, inputs.item, [result.defect],
                              set(result.expected), inputs.spec_text)
        if problems:
            c["rejected"] += 1
            rejected.append(rejected_from_validation(result, problems))
            continue
        candidates.append(result)

    cases, duplicates = assign_case_ids(candidates)
    for d in duplicates:
        counts[d.operator]["duplicates"] += 1
    for case in cases:
        counts[case.candidate.site.operator]["accepted"] += 1

    paths = input_paths(system)
    manifest = {
        "generator": "tara_verification.injection",
        "version": __version__,
        "code": _code_state(),
        "inputs": {
            "system": system,
            "rev": rev,
            "files": {paths["tara"]: inputs.tara_sha256, paths["item"]: inputs.item_sha256,
                      paths["spec"]: inputs.spec_sha256},
        },
        "seed": seed,
        "split": split,
        "scenarios": scenarios,
        "operators": operators,
        "counts": counts,
        "total_cases": len(cases),
        "known_issues": [code for code, s, _ in KNOWN_ISSUES if s in (system, "all")],
        "known_violations": [list(v) for v in sorted(KNOWN_VIOLATIONS.get(system, ()))],
        "skipped": [s.to_dict() for s in skipped],
        "duplicates": [d.to_dict() for d in duplicates],
    }
    prepare_out(out, overwrite)
    write_dataset(out, inputs=inputs, split=split, seed=seed, cases=cases,
                  rejected=rejected, manifest=manifest)
    return manifest


def _code_state() -> dict:
    """Commit of this code, and whether the package source has local changes."""
    here = Path(__file__).resolve().parent
    src = here.parents[1]

    def git(*args):
        r = subprocess.run(["git", "-C", str(here), *args], capture_output=True, text=True,
                           check=False)
        return r.stdout.strip() if r.returncode == 0 else None

    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--", str(src))
    return {"commit": commit, "dirty": bool(status) if status is not None else None}


def _parse_sha(values: list[str]) -> dict[str, str] | None:
    if not values:
        return None
    out = {}
    for v in values:
        role, sep, digest = v.partition("=")
        if not sep:
            raise ValueError(f"--expect-sha256 needs ROLE=HASH, got {v!r}")
        out[role] = digest
    return out


def _csv(text: str) -> list[str]:
    return [x.strip() for x in text.split(",") if x.strip()]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="python -m tara_verification.injection",
        description="Inject defects into a reference TARA and write cases and labels. "
                    "No model is called; the same seed gives byte-identical output.")
    p.add_argument("--repo", type=Path, default=Path("."), help="repository root (default: .)")
    p.add_argument("--system", required=True, help="system directory name, for example bbw")
    p.add_argument("--scenarios", required=True, type=_csv,
                   help="comma-separated threat scenario IDs")
    p.add_argument("--operators", required=True, type=_csv,
                   help=f"comma-separated operators from {', '.join(OPERATORS)}")
    p.add_argument("--seed", required=True, type=int)
    p.add_argument("--out", required=True, type=Path, help="output dataset directory")
    p.add_argument("--rev", default=BASELINE_REV,
                   help=f"git revision of the inputs (default: {BASELINE_REV}); "
                        "use 'worktree' to read the working tree")
    p.add_argument("--split", default="dev", help="split directory name (default: dev)")
    p.add_argument("--expect-sha256", action="append", default=[], metavar="ROLE=HASH",
                   help="expected input hash; ROLE is tara, item or spec. "
                        "The pinned hashes apply by default for the baseline revision")
    p.add_argument("--overwrite", action="store_true",
                   help="replace an existing dataset directory that has a manifest.json")
    args = p.parse_args(argv)
    try:
        manifest = run(repo=args.repo, system=args.system, scenarios=args.scenarios,
                       operators=args.operators, seed=args.seed, out=args.out,
                       rev=None if args.rev == "worktree" else args.rev, split=args.split,
                       overwrite=args.overwrite, expected_sha256=_parse_sha(args.expect_sha256))
    except (InputError, DatasetError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"wrote {manifest['total_cases']} cases to {args.out}", file=sys.stderr)
    for op, c in manifest["counts"].items():
        print(f"  {op}: " + ", ".join(f"{k} {c[k]}" for k in COUNT_KEYS), file=sys.stderr)
    for s in manifest["skipped"]:
        print(f"  skipped {s['operator']} {s['object_id']}:{s['field']}: {s['reasons'][0]}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
