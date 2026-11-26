"""Write cases, labels, rejected cases and the manifest of a dataset.

Layout (labels stay outside the split directory that reviewers see):

    <out>/manifest.json
    <out>/rejected.jsonl
    <out>/labels/<case_id>.json
    <out>/<split>/context/item-definition.json
    <out>/<split>/context/functional-specification.txt
    <out>/<split>/cases/<case_id>/tara.json
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

from ..contract import Base, Label, check_label, to_dict
from .load import Inputs, canonical
from .operators import Candidate

CASE_ID_LENGTH = 6


class DatasetError(Exception):
    """The dataset cannot be written safely."""


@dataclass(frozen=True)
class Rejected:
    operator: str
    scenario_id: str
    object_id: str
    field: str
    stage: str  # "skip", "validate" or "duplicate"
    reasons: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps({"operator": self.operator, "scenario_id": self.scenario_id,
                           "object_id": self.object_id, "field": self.field,
                           "stage": self.stage, "reasons": list(self.reasons)},
                          ensure_ascii=False)


@dataclass(frozen=True)
class Case:
    case_id: str
    text: str  # canonical TARA
    candidate: Candidate


def case_id_of(text: str) -> str:
    return "c-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:CASE_ID_LENGTH]


def assign_case_ids(candidates: list[Candidate]) -> tuple[list[Case], list[Rejected]]:
    """Give each candidate a content-hash ID. Identical content is dropped as
    a duplicate; a different content with the same short ID is a hash
    collision and stops the run."""
    cases: dict[str, Case] = {}
    duplicates = []
    for c in candidates:
        text = canonical(c.mutant)
        cid = case_id_of(text)
        if cid in cases:
            if cases[cid].text != text:
                raise DatasetError(f"case_id collision: {cid} for different content; "
                                   f"increase CASE_ID_LENGTH")
            first = cases[cid].candidate.site
            duplicates.append(_rejected(c, "duplicate", [
                f"same content as {cid} ({first.operator} at {first.object_id}:{first.field})"]))
            continue
        cases[cid] = Case(cid, text, c)
    return list(cases.values()), duplicates


def rejected_from_skip(skip) -> Rejected:
    s = skip.site
    return Rejected(s.operator, s.scenario_id, s.object_id, s.field, "skip", (skip.reason,))


def rejected_from_validation(candidate: Candidate, reasons: list[str]) -> Rejected:
    return _rejected(candidate, "validate", reasons)


def _rejected(c: Candidate, stage: str, reasons: list[str]) -> Rejected:
    s = c.site
    return Rejected(s.operator, s.scenario_id, s.object_id, s.field, stage, tuple(reasons))


def build_label(case: Case, inputs: Inputs, split: str, seed: int) -> Label:
    label = Label(
        case_id=case.case_id,
        base=Base(system=inputs.system, tag=inputs.rev or "working-tree",
                  tara_sha256=inputs.tara_sha256, item_sha256=inputs.item_sha256),
        split=split, case_type="single", seed=seed, defects=(case.candidate.defect,),
    )
    problems = check_label(label)
    if problems:
        raise DatasetError(f"{case.case_id}: invalid label: {problems}")
    return label


def prepare_out(out: Path, overwrite: bool) -> None:
    """Create an empty output directory. An existing non-empty directory is
    replaced only with overwrite=True and only if it holds a manifest.json,
    so the writer never deletes a directory it did not create."""
    if out.exists() and any(out.iterdir()):
        if not overwrite:
            raise DatasetError(f"{out} is not empty; pass --overwrite to replace it")
        if not (out / "manifest.json").is_file():
            raise DatasetError(f"{out} has no manifest.json; refusing to delete it")
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)


def write_dataset(out: Path, *, inputs: Inputs, split: str, seed: int, cases: list[Case],
                  rejected: list[Rejected], manifest: dict) -> None:
    """Write a prepared dataset. Call prepare_out() first."""
    context = out / split / "context"
    context.mkdir(parents=True)
    (context / "item-definition.json").write_bytes(inputs.item_bytes)
    (context / "functional-specification.txt").write_bytes(inputs.spec_bytes)
    labels = out / "labels"
    labels.mkdir()
    for case in sorted(cases, key=lambda c: c.case_id):
        case_dir = out / split / "cases" / case.case_id
        case_dir.mkdir(parents=True)
        (case_dir / "tara.json").write_text(case.text, "utf-8")
        label = build_label(case, inputs, split, seed)
        (labels / f"{case.case_id}.json").write_text(
            json.dumps(to_dict(label), indent=2, ensure_ascii=False) + "\n", "utf-8")
    (out / "rejected.jsonl").write_text("".join(r.to_json() + "\n" for r in rejected), "utf-8")
    (out / "manifest.json").write_text(
        json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", "utf-8")
