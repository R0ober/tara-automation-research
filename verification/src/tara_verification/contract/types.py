"""Label and finding types shared by the injector, the reviewers and evaluation.

A label is ground truth and is never visible to a reviewer. A finding is what
a reviewer reports. Both use the same Location and Evidence types so that
evaluation can match them. Change these types only after updating ADR 0001.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

CATEGORIES = ("contradiction", "infeasible", "unsupported")
TIERS = ("M", "S", "L")
ORIGINS = ("historical", "synthetic")
POLICIES = ("local", "propagated")
CASE_TYPES = ("single", "triple", "clean", "benign")
DOCUMENTS = ("tara", "item_definition", "functional_specification")
# "quote": the quote occurs in the resolved field.
# "absent": the quote (an ID) is not defined anywhere in the document.
RELATIONS = ("quote", "absent")


@dataclass(frozen=True)
class Location:
    scenario_id: str
    object_id: str
    field: str

    @classmethod
    def from_dict(cls, d: dict) -> Location:
        return cls(d["scenario_id"], d["object_id"], d["field"])


@dataclass(frozen=True)
class Evidence:
    document: str
    object_id: str | None
    field: str | None
    quote: str | None
    relation: str = "quote"

    @classmethod
    def from_dict(cls, d: dict) -> Evidence:
        return cls(d["document"], d.get("object_id"), d.get("field"),
                   d.get("quote"), d.get("relation", "quote"))


@dataclass(frozen=True)
class Edit:
    path: str  # RFC 6901 JSON pointer; internal coordinates, may contain indices
    before: Any
    after: Any

    @classmethod
    def from_dict(cls, d: dict) -> Edit:
        return cls(d["path"], d["before"], d["after"])


@dataclass(frozen=True)
class Effect:
    band_changed: bool
    risk_changed: bool

    @classmethod
    def from_dict(cls, d: dict) -> Effect:
        return cls(d["band_changed"], d["risk_changed"])


@dataclass(frozen=True)
class Defect:
    defect_id: str
    category: str
    operator: str
    tier: str
    origin: str
    policy: str
    location: Location
    accepted_locations: tuple[Location, ...]
    evidence: tuple[Evidence, ...]
    effect: Effect
    edits: tuple[Edit, ...]

    @classmethod
    def from_dict(cls, d: dict) -> Defect:
        return cls(
            defect_id=d["defect_id"],
            category=d["category"],
            operator=d["operator"],
            tier=d["tier"],
            origin=d["origin"],
            policy=d["policy"],
            location=Location.from_dict(d["location"]),
            accepted_locations=tuple(Location.from_dict(x) for x in d["accepted_locations"]),
            evidence=tuple(Evidence.from_dict(x) for x in d["evidence"]),
            effect=Effect.from_dict(d["effect"]),
            edits=tuple(Edit.from_dict(x) for x in d["edits"]),
        )


@dataclass(frozen=True)
class Base:
    system: str
    tag: str  # a commit during development; a tag for v1
    tara_sha256: str
    item_sha256: str

    @classmethod
    def from_dict(cls, d: dict) -> Base:
        return cls(d["system"], d["tag"], d["tara_sha256"], d["item_sha256"])


@dataclass(frozen=True)
class Label:
    case_id: str
    base: Base
    split: str
    case_type: str
    seed: int
    defects: tuple[Defect, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, d: dict) -> Label:
        return cls(
            case_id=d["case_id"],
            base=Base.from_dict(d["base"]),
            split=d["split"],
            case_type=d["case_type"],
            seed=d["seed"],
            defects=tuple(Defect.from_dict(x) for x in d["defects"]),
        )


@dataclass(frozen=True)
class Finding:
    category: str
    location: Location
    claim: str
    evidence: tuple[Evidence, ...]

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(d["category"], Location.from_dict(d["location"]), d["claim"],
                   tuple(Evidence.from_dict(x) for x in d["evidence"]))


def to_dict(obj: Any) -> dict:
    """Convert a contract dataclass to plain JSON data (tuples become lists)."""
    return _plain(asdict(obj))


def _plain(x: Any) -> Any:
    if isinstance(x, dict):
        return {k: _plain(v) for k, v in x.items()}
    if isinstance(x, (list, tuple)):
        return [_plain(v) for v in x]
    return x


def check_label(label: Label) -> list[str]:
    """Return problems with enumerated values in a label (empty if none)."""
    problems = []
    if label.case_type not in CASE_TYPES:
        problems.append(f"unknown case_type {label.case_type!r}")
    if label.case_type == "clean" and label.defects:
        problems.append("clean case has defects")
    if label.case_type == "single" and len(label.defects) != 1:
        problems.append(f"single case has {len(label.defects)} defects")
    seen = set()
    for d in label.defects:
        if d.defect_id in seen:
            problems.append(f"duplicate defect_id {d.defect_id!r}")
        seen.add(d.defect_id)
        for name, value, allowed in (("category", d.category, CATEGORIES),
                                     ("tier", d.tier, TIERS),
                                     ("origin", d.origin, ORIGINS),
                                     ("policy", d.policy, POLICIES)):
            if value not in allowed:
                problems.append(f"{d.defect_id}: unknown {name} {value!r}")
        if not d.edits:
            problems.append(f"{d.defect_id}: no edits")
        problems += _check_evidence(d.defect_id, d.evidence)
    return problems


def check_finding(finding: Finding) -> list[str]:
    """Return problems with enumerated values in a finding (empty if none)."""
    problems = []
    if finding.category not in CATEGORIES:
        problems.append(f"unknown category {finding.category!r}")
    return problems + _check_evidence("finding", finding.evidence)


def _check_evidence(owner: str, evidence: tuple[Evidence, ...]) -> list[str]:
    problems = []
    for e in evidence:
        if e.document not in DOCUMENTS:
            problems.append(f"{owner}: unknown evidence document {e.document!r}")
        if e.relation not in RELATIONS:
            problems.append(f"{owner}: unknown evidence relation {e.relation!r}")
        if e.relation == "absent" and not e.quote:
            problems.append(f"{owner}: absent evidence needs the missing ID as quote")
    return problems
