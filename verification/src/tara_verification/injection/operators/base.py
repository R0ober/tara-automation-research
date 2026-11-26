"""Shared operator types and helpers.

Operators read methodology tables with their own helpers here; they never
call validate.violations() or its helpers, so expected violations stay
hand-written.

Effect semantics (normative definition in ADR 0001):
    band_changed  the edit changes a feasibility band, stated or implied by
                  the edited numbers, at the edited node.
    risk_changed  a correct propagation of the edit would change the
                  inherent risk value.
"""

from __future__ import annotations

import copy
import random
import re
from dataclasses import dataclass
from typing import Any

from ...contract import Defect, Edit, Effect, Evidence, Location
from ..index import all_ids, item_definition_ids
from ..load import canonical
from ..pointer import get_at, set_at, to_rfc6901
from ..sites import Site
from ..validate import Violation

SUMMARY = "traceability_and_risk_summary"

_RANGE_RE = re.compile(r"^\s*(-?\d+)\s*-\s*(-?\d+)\s*$")
_BOUND_RE = re.compile(r"^\s*(>=|<=|>|<)\s*(-?\d+)\s*$")


@dataclass(frozen=True)
class Context:
    tara: dict
    item: dict
    item_ids: dict[str, set[str]]
    known_ids: frozenset[str]
    text: str  # canonical TARA plus item definition, for "never seen" checks

    @property
    def methodology(self) -> dict:
        return self.tara["tara_metadata"]["methodology"]


def make_context(tara: dict, item: dict) -> Context:
    return Context(tara=tara, item=item, item_ids=item_definition_ids(item),
                   known_ids=frozenset(all_ids(item, tara)),
                   text=canonical(tara) + canonical(item))


@dataclass(frozen=True)
class Candidate:
    site: Site
    mutant: dict
    defect: Defect
    expected: frozenset[Violation]


@dataclass(frozen=True)
class Skip:
    site: Site
    reason: str


def site_rng(seed: int, site: Site) -> random.Random:
    """Per-site generator: adding or removing a site never changes other cases."""
    key = "|".join((str(seed), site.operator, site.scenario_id, site.object_id, site.field,
                    to_rfc6901(site.pointer)))
    return random.Random(key)  # str seeds are hashed with SHA-512, not hash()


def mutate(tara: dict, changes: list[tuple[tuple, Any]]) -> tuple[dict, tuple[Edit, ...]]:
    """Deep-copy the baseline and apply (pointer, new value) changes."""
    mutant = copy.deepcopy(tara)
    edits = []
    for ptr, value in changes:
        edits.append(Edit(to_rfc6901(ptr), copy.deepcopy(get_at(tara, ptr)), value))
        set_at(mutant, ptr, value)
    return mutant, tuple(edits)


def defect(site: Site, *, operator: str, origin: str, edits: tuple[Edit, ...],
           evidence: list[Evidence], effect: Effect,
           accepted: list[Location] = ()) -> Defect:
    return Defect(
        defect_id="d1", category="contradiction", operator=operator, tier="M",
        origin=origin, policy="local",
        location=Location(site.scenario_id, site.object_id, site.field),
        accepted_locations=tuple(accepted), evidence=tuple(evidence), effect=effect,
        edits=edits,
    )


def scenario_of(ctx: Context, site: Site) -> dict:
    for s in ctx.tara["threat_scenarios_and_attack_trees"]:
        if s["threat_scenario_id"] == site.scenario_id:
            return s
    raise KeyError(site.scenario_id)


# --- methodology helpers (independent of validate.py) -----------------------

def band_key(score: int, mapping: dict[str, str]) -> str | None:
    """The feasibility_mapping key whose range contains the score."""
    for key in mapping:
        m = _RANGE_RE.match(key)
        if m and int(m[1]) <= score <= int(m[2]):
            return key
        m = _BOUND_RE.match(key)
        if m:
            n = int(m[2])
            if {">=": score >= n, "<=": score <= n, ">": score > n, "<": score < n}[m[1]]:
                return key
    return None


def band_of(score: int | None, mapping: dict[str, str]) -> str | None:
    if score is None:
        return None
    key = band_key(score, mapping)
    return mapping[key] if key is not None else None


def bands(mapping: dict[str, str]) -> list[str]:
    """Distinct bands in methodology order."""
    return list(dict.fromkeys(mapping.values()))


def risk_max(matrix: dict) -> int:
    return max(v for row in matrix.values() for v in row.values())


def lookup_risk(matrix: dict, impact: str | None, band: str | None) -> int | None:
    row = matrix.get(impact)
    return row.get(band) if isinstance(row, dict) else None


def implied_score(node: dict, leaf_id: str, new_total: int) -> int | None:
    """Node score if leaf_id had total new_total. OR takes the lowest child.

    An AND node keeps its stated aggregate, because the methodology scores
    the complete path once and a child total does not determine it.
    """
    if node.get("node_id") == leaf_id:
        return new_total
    ap = node.get("attack_potential")
    if isinstance(ap, dict):
        return ap.get("total_score")
    children = node.get("children") or []
    if not children:
        return None
    if node.get("gate") != "OR":
        return node.get("aggregated_attack_potential_score")
    scores = [s for s in (implied_score(c, leaf_id, new_total) for c in children) if s is not None]
    return min(scores) if scores else None
