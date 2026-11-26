"""C4: a feasibility band or a risk value disagrees with its inputs."""

from __future__ import annotations

import random

from ...contract import Effect, Evidence, Location
from ..pointer import get_at
from ..sites import Site
from ..validate import Violation
from .base import (
    SUMMARY, Candidate, Context, Skip, band_key, bands, defect, lookup_risk, mutate, risk_max,
    scenario_of,
)

LEAF_BAND = "attack_potential.feasibility_rating"
ROOT_BAND = "aggregated_attack_feasibility"
RD_BAND = "risk_determination.aggregated_attack_feasibility"
RD_RISK = "risk_determination.inherent_risk_value"


def apply(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    if site.field == RD_RISK:
        return _risk(ctx, site, rng)
    return _band(ctx, site, rng)


def _band(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    current = get_at(ctx.tara, site.pointer)
    mapping = ctx.methodology["feasibility_mapping"]
    others = [b for b in bands(mapping) if b != current]
    if not others:
        return Skip(site, "the feasibility mapping has no other band")
    new = rng.choice(others)
    mutant, edits = mutate(ctx.tara, [(site.pointer, new)])

    s = scenario_of(ctx, site)
    ts = site.scenario_id
    root = s["attack_tree"]
    rd = s["risk_determination"]
    value = rd.get("inherent_risk_value")
    lookup_changes = value is not None and lookup_risk(
        ctx.methodology["risk_matrix"], rd["overall_impact_rating"], new) != value
    accepted: list[Location] = []

    if site.field == LEAF_BAND:
        score = get_at(ctx.tara, site.pointer[:-1])["total_score"]
        expected = {Violation("R-BAND", site.object_id, LEAF_BAND)}
        evidence = [Evidence("tara", site.object_id, "attack_potential.total_score", str(score)),
                    _mapping_evidence(score, mapping)]
        risk_changed = False  # a node band is not an input of the risk lookup
    elif site.field == ROOT_BAND:
        score = root["aggregated_attack_potential_score"]
        expected = {Violation("R-BAND", site.object_id, ROOT_BAND),
                    Violation("R-AGG", ts, RD_BAND)}
        accepted.append(Location(ts, ts, RD_BAND))
        evidence = [Evidence("tara", site.object_id, "aggregated_attack_potential_score",
                             str(score)),
                    _mapping_evidence(score, mapping)]
        risk_changed = lookup_changes
    elif site.field == RD_BAND:
        expected = {Violation("R-AGG", ts, RD_BAND),
                    Violation("R-SUMMARY", ts, f"{SUMMARY}.inherent_feasibility")}
        if lookup_changes:
            expected.add(Violation("R-RISK", ts, RD_RISK))
        accepted.append(Location(ts, root["node_id"], ROOT_BAND))
        evidence = [Evidence("tara", root["node_id"], ROOT_BAND, current)]
        risk_changed = lookup_changes
    else:
        return Skip(site, f"no C4 rule for field {site.field!r}")

    d = defect(site, operator="C4", origin="synthetic", edits=edits, evidence=evidence,
               effect=Effect(band_changed=True, risk_changed=risk_changed), accepted=accepted)
    return Candidate(site, mutant, d, frozenset(expected))


def _risk(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    """Change inherent_risk_value and inherent_risk_level together."""
    s = scenario_of(ctx, site)
    rd = s["risk_determination"]
    matrix = ctx.methodology["risk_matrix"]
    impact, band = rd["overall_impact_rating"], rd["aggregated_attack_feasibility"]
    correct, current, top = lookup_risk(matrix, impact, band), rd["inherent_risk_value"], risk_max(matrix)
    if correct is None:
        return Skip(site, f"no matrix entry for {impact!r} and {band!r}")
    if rd.get("inherent_risk_level") != f"{current} / {top}":
        return Skip(site, "inherent_risk_level does not state the current value")
    choices = [v for v in range(1, top + 1) if v not in (correct, current)]
    new = rng.choice(choices)
    level_ptr = (*site.pointer[:-1], "inherent_risk_level")
    mutant, edits = mutate(ctx.tara, [(site.pointer, new), (level_ptr, f"{new} / {top}")])
    ts = site.scenario_id
    d = defect(site, operator="C4", origin="synthetic", edits=edits,
               effect=Effect(band_changed=False, risk_changed=True),
               evidence=[
                   Evidence("tara", ts, "risk_determination.overall_impact_rating", impact),
                   Evidence("tara", ts, RD_BAND, band),
                   Evidence("tara", "tara_metadata", f"methodology.risk_matrix.{impact}.{band}",
                            str(correct)),
               ])
    expected = frozenset({Violation("R-RISK", ts, RD_RISK),
                          Violation("R-SUMMARY", ts, f"{SUMMARY}.inherent_risk")})
    return Candidate(site, mutant, d, expected)


def _mapping_evidence(score: int, mapping: dict[str, str]) -> Evidence:
    key = band_key(score, mapping)
    return Evidence("tara", "tara_metadata", f"methodology.feasibility_mapping.{key}",
                    mapping[key])
