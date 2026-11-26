"""C1a (dangling reference) and C1b (malformed reference) on item-definition IDs."""

from __future__ import annotations

import random
import re
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


_TRAILING_NUMBER_RE = re.compile(r"^(?P<stem>.*?)(?P<number>\d+)$")


def dangling_ids(value: str, ctx: Context) -> list[str]:
    """Plausible IDs that occur nowhere in either document, sorted.

    If the ID ends in a number, only that number changes, to a value from 1
    to 9 with the same width (ASSET-BRK-01 -> ASSET-BRK-07), so the new ID
    stays close to the existing ones. Otherwise one
    letter of the last segment changes (INT-SWD-HEADER -> INT-SWD-HEAXER).
    """
    m = _TRAILING_NUMBER_RE.match(value)
    if m:
        width = len(m["number"])
        variants = (f"{m['stem']}{n:0{width}d}" for n in range(1, 10))
    else:
        head, sep, last = value.rpartition("-")
        variants = (f"{head}{sep}{last[:i]}{r}{last[i + 1:]}"
                    for i, ch in enumerate(last) if ch.isupper()
                    for r in string.ascii_uppercase if r != ch)
    return sorted({v for v in variants
                   if v != value and v not in ctx.known_ids and v not in ctx.text})


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
