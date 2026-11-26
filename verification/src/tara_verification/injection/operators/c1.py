"""C1a (dangling reference) and C1b (malformed reference) on item-definition IDs."""

from __future__ import annotations

import random
import string

from ...contract import Effect, Evidence
from ..index import connection_components, interface_components, interface_connection
from ..pointer import get_at
from ..sites import Site
from ..validate import Violation
from .base import SUMMARY, Candidate, Context, Skip, defect, mutate, scenario_of

NO_EFFECT = Effect(band_changed=False, risk_changed=False)


def expected_violations(site: Site) -> frozenset[Violation]:
    """Hand-written; see the expected-violation table in CLAUDE.md."""
    ts = site.scenario_id
    out = {Violation("R-REF", site.object_id, site.field)}
    if site.field == "targeted_asset.asset_id":
        out.add(Violation("R-SUMMARY", ts, f"{SUMMARY}.asset_id"))
    elif site.field == "associated_damage_scenario.damage_id":
        out.add(Violation("R-SUMMARY", ts, f"{SUMMARY}.damage_id"))
    elif site.field.startswith(SUMMARY + "."):
        out.add(Violation("R-SUMMARY", ts, site.field))
    return frozenset(out)


def dangling_ids(value: str, ctx: Context) -> list[str]:
    """Same-prefix IDs that differ in one character of the last segment and
    occur nowhere in either document, sorted."""
    head, sep, last = value.rpartition("-")
    out = set()
    for i, ch in enumerate(last):
        if ch.isdigit():
            pool = string.digits
        elif ch.isupper():
            pool = string.ascii_uppercase
        else:
            continue
        for r in pool:
            if r == ch:
                continue
            new = f"{head}{sep}{last[:i]}{r}{last[i + 1:]}"
            if new not in ctx.known_ids and new not in ctx.text:
                out.add(new)
    return sorted(out)


def apply_c1a(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    value = get_at(ctx.tara, site.pointer)
    candidates = dangling_ids(value, ctx)
    if not candidates:
        return Skip(site, f"no unused ID with the prefix of {value!r}")
    new = rng.choice(candidates)
    mutant, edits = mutate(ctx.tara, [(site.pointer, new)])
    d = defect(site, operator="C1a", origin="synthetic", edits=edits, effect=NO_EFFECT,
               evidence=[Evidence("item_definition", None, None, new, "absent"),
                         Evidence("tara", site.object_id, site.field, new)])
    return Candidate(site, mutant, d, expected_violations(site))


def apply_c1b(ctx: Context, site: Site, rng: random.Random) -> Candidate | Skip:
    value = get_at(ctx.tara, site.pointer)
    if site.kind == "interface":
        new = _interface_combination(ctx, value)
    elif site.kind == "component":
        new = _component_combination(ctx, site, value, rng)
    else:
        return Skip(site, f"no C1b combination rule for {site.kind} fields")
    if new is None:
        return Skip(site, f"no partner ID for {value!r}")
    mutant, edits = mutate(ctx.tara, [(site.pointer, new)])
    d = defect(site, operator="C1b", origin="historical", edits=edits, effect=NO_EFFECT,
               evidence=[Evidence("tara", site.object_id, site.field, new)])
    return Candidate(site, mutant, d, expected_violations(site))


def _interface_combination(ctx: Context, value: str) -> str | None:
    """With its connection if it has one, otherwise with its owning component."""
    conn = interface_connection(ctx.item).get(value)
    if conn:
        return f"{value} ({conn})"
    owners = interface_components(ctx.item).get(value) or []
    return f"{value} ({owners[0]})" if owners else None


def _component_combination(ctx: Context, site: Site, value: str,
                           rng: random.Random) -> str | None:
    """With another component on the same connection.

    Connections named by the site context come first: the asset's
    associated connections, or the connection of the node's target
    interface. Otherwise any connection of the component is used.
    """
    on_conn = connection_components(ctx.item)
    preferred: list[str] = []
    if site.field == "targeted_asset.parent_component":
        preferred = list(scenario_of(ctx, site)["targeted_asset"].get("associated_connections") or [])
    elif site.field == "target_component" and "attack_tree" in site.pointer:
        node = get_at(ctx.tara, site.pointer[:-1])
        conn = interface_connection(ctx.item).get(node.get("target_interface"))
        preferred = [conn] if conn else []
    for conns in (preferred, list(on_conn)):
        peers = sorted({p for c in conns if value in on_conn.get(c, [])
                        for p in on_conn[c] if p != value})
        if peers:
            return f"{value} / {rng.choice(peers)}"
    return None
