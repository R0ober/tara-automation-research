"""C3: a factor score disagrees with its label, or a total disagrees with its factors."""

from __future__ import annotations

import random

from ...contract import Effect, Evidence, Location
from ..pointer import get_at
from ..sites import Site
from ..validate import Violation
from .base import (
    Candidate, Context, Skip, band_of, defect, implied_score, lookup_risk, mutate, scenario_of,
)

TOTAL = "attack_potential.total_score"
OFFSETS = (-3, -2, -1, 1, 2, 3)


def apply(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    if site.field == TOTAL:
        return _total(ctx, site, rng)
    return _factor(ctx, site, rng)


def _factor(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    factor = site.field.split(".")[1]
    ap = get_at(ctx.tara, site.pointer[:-2])
    label, current = ap[factor]["label"], ap[factor]["score"]
    table = ctx.methodology["attack_potential_parameters"][factor]
    others = sorted({v for v in table.values() if v != current})
    if not others:
        return Skip(site, f"the {factor} table has no other score")
    new = rng.choice(others)
    mutant, edits = mutate(ctx.tara, [(site.pointer, new)])

    s = scenario_of(ctx, site)
    mapping = ctx.methodology["feasibility_mapping"]
    new_total = ap["total_score"] - current + new
    root_score = implied_score(s["attack_tree"], site.object_id, new_total)
    rd = s["risk_determination"]
    new_risk = lookup_risk(ctx.methodology["risk_matrix"], rd["overall_impact_rating"],
                           band_of(root_score, mapping))
    effect = Effect(
        band_changed=band_of(new_total, mapping) != ap["feasibility_rating"],
        risk_changed=rd.get("inherent_risk_value") is not None
        and new_risk != rd["inherent_risk_value"],
    )
    d = defect(site, operator="C3", origin="synthetic", edits=edits, effect=effect,
               accepted=[Location(site.scenario_id, site.object_id, TOTAL)],
               evidence=[
                   Evidence("tara", site.object_id, f"attack_potential.{factor}.label", label),
                   Evidence("tara", "tara_metadata",
                            f"methodology.attack_potential_parameters.{factor}.{label}",
                            str(table[label])),
               ])
    expected = frozenset({Violation("R-SCORE", site.object_id, site.field),
                          Violation("R-SUM", site.object_id, TOTAL)})
    return Candidate(site, mutant, d, expected)


def _total(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    ap = get_at(ctx.tara, site.pointer[:-1])
    current = ap["total_score"]
    mapping = ctx.methodology["feasibility_mapping"]
    band = band_of(current, mapping)
    valid = [current + d for d in OFFSETS
             if current + d >= 0 and band_of(current + d, mapping) == band]
    if not valid:
        return Skip(site, f"no offset of {current} keeps the {band} band")
    new = rng.choice(valid)
    mutant, edits = mutate(ctx.tara, [(site.pointer, new)])

    # pointer = (..., parent, "children", i, "attack_potential", "total_score")
    parent = get_at(ctx.tara, site.pointer[:-4])
    expected = {Violation("R-SUM", site.object_id, TOTAL)}
    accepted = []
    if implied_score(parent, site.object_id, new) != parent.get("aggregated_attack_potential_score"):
        expected.add(Violation("R-AGG", parent["node_id"], "aggregated_attack_potential_score"))
        accepted.append(Location(site.scenario_id, parent["node_id"],
                                 "aggregated_attack_potential_score"))
    factors = ctx.methodology["attack_potential_parameters"]
    d = defect(site, operator="C3", origin="synthetic", edits=edits,
               effect=Effect(band_changed=False, risk_changed=False), accepted=accepted,
               evidence=[Evidence("tara", site.object_id, f"attack_potential.{f}.score",
                                  str(ap[f]["score"])) for f in factors])
    return Candidate(site, mutant, d, frozenset(expected))
