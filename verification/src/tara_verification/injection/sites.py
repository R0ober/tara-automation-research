"""Enumerate the injectable sites of a TARA.

A site has human coordinates (scenario_id, object_id, field), which go into
the label location, and an internal pointer, which may contain list indices
and is used only to apply the edit.
"""

from __future__ import annotations

from dataclasses import dataclass

SUMMARY = "traceability_and_risk_summary"
C1_OPERATORS = ("C1a", "C1b")
OPERATORS = ("C1a", "C1b", "C3", "C4")


@dataclass(frozen=True)
class Site:
    operator: str      # "C3"
    scenario_id: str   # "TS-BRK-01"
    object_id: str     # "AT-BRK-01-B3"
    field: str         # "attack_potential.equipment.score"
    pointer: tuple     # internal only, may contain list indices
    kind: str | None = None  # C1 only: the ID kind the field must hold


def enumerate_sites(tara: dict, scenario_ids: list[str], operators: list[str]) -> list[Site]:
    """Sites in file order: by scenario, then by operator, then by position."""
    unknown = [op for op in operators if op not in OPERATORS]
    if unknown:
        raise ValueError(f"unknown operators: {unknown}")
    scenarios = tara["threat_scenarios_and_attack_trees"]
    by_id = {s["threat_scenario_id"]: i for i, s in enumerate(scenarios)}
    missing = [ts for ts in scenario_ids if ts not in by_id]
    if missing:
        raise ValueError(f"unknown scenarios: {missing}")
    rows = {r["threat_scenario_id"]: i for i, r in enumerate(tara.get(SUMMARY, []))}
    factors = list(tara["tara_metadata"]["methodology"]["attack_potential_parameters"])

    out: list[Site] = []
    for ts in scenario_ids:
        si = by_id[ts]
        for op in operators:
            if op in C1_OPERATORS:
                found = _reference_sites(tara, si, rows.get(ts))
            elif op == "C3":
                found = _score_sites(tara, si, factors)
            else:
                found = _band_and_risk_sites(tara, si)
            out += [Site(op, ts, obj, field, ptr, kind) for obj, field, ptr, kind in found]
    return out


def _reference_sites(tara: dict, si: int, row: int | None):
    """Fields that hold an item-definition ID. Null values are skipped (B7)."""
    s = tara["threat_scenarios_and_attack_trees"][si]
    ts = s["threat_scenario_id"]
    sp = ("threat_scenarios_and_attack_trees", si)
    found = [
        (ts, "targeted_asset.asset_id", (*sp, "targeted_asset", "asset_id"), "asset"),
        (ts, "targeted_asset.parent_component",
         (*sp, "targeted_asset", "parent_component"), "component"),
    ]
    for i, _ in enumerate(s["targeted_asset"].get("associated_connections") or []):
        found.append((ts, "targeted_asset.associated_connections",
                      (*sp, "targeted_asset", "associated_connections", i), "connection"))
    found.append((ts, "associated_damage_scenario.damage_id",
                  (*sp, "associated_damage_scenario", "damage_id"), "damage"))
    for ptr, node in _node_pointers(s["attack_tree"], (*sp, "attack_tree")):
        if "target_component" in node:
            found.append((node["node_id"], "target_component", (*ptr, "target_component"),
                          "component"))
        if "target_interface" in node:
            found.append((node["node_id"], "target_interface", (*ptr, "target_interface"),
                          "interface"))
    reqs = (s.get("proposed_risk_treatment") or {}).get("cybersecurity_requirements") or []
    for i, r in enumerate(reqs):
        found.append((r["requirement_id"], "target_component",
                      (*sp, "proposed_risk_treatment", "cybersecurity_requirements", i,
                       "target_component"), "component"))
    if row is not None:
        for field, kind in (("asset_id", "asset"), ("damage_id", "damage")):
            found.append((ts, f"{SUMMARY}.{field}", (SUMMARY, row, field), kind))
    return [f for f in found if _get(tara, f[2]) is not None]


def _score_sites(tara: dict, si: int, factors: list[str]):
    """The five factor scores and the total of every scored node."""
    s = tara["threat_scenarios_and_attack_trees"][si]
    found = []
    for ptr, node in _node_pointers(s["attack_tree"],
                                    ("threat_scenarios_and_attack_trees", si, "attack_tree")):
        if not isinstance(node.get("attack_potential"), dict):
            continue
        ap = (*ptr, "attack_potential")
        for f in factors:
            found.append((node["node_id"], f"attack_potential.{f}.score", (*ap, f, "score"), None))
        found.append((node["node_id"], "attack_potential.total_score", (*ap, "total_score"), None))
    return found


def _band_and_risk_sites(tara: dict, si: int):
    """Stated bands of scored nodes and of the aggregate, and the risk value."""
    s = tara["threat_scenarios_and_attack_trees"][si]
    ts = s["threat_scenario_id"]
    sp = ("threat_scenarios_and_attack_trees", si)
    found = []
    for ptr, node in _node_pointers(s["attack_tree"], (*sp, "attack_tree")):
        ap = node.get("attack_potential")
        if isinstance(ap, dict) and ap.get("feasibility_rating") is not None:
            found.append((node["node_id"], "attack_potential.feasibility_rating",
                          (*ptr, "attack_potential", "feasibility_rating"), None))
        if node.get("children") and node.get("aggregated_attack_feasibility") is not None:
            found.append((node["node_id"], "aggregated_attack_feasibility",
                          (*ptr, "aggregated_attack_feasibility"), None))
    rd = s.get("risk_determination") or {}
    if rd.get("aggregated_attack_feasibility") is not None:
        found.append((ts, "risk_determination.aggregated_attack_feasibility",
                      (*sp, "risk_determination", "aggregated_attack_feasibility"), None))
    if rd.get("inherent_risk_value") is not None:  # a null risk stays open (B6)
        found.append((ts, "risk_determination.inherent_risk_value",
                      (*sp, "risk_determination", "inherent_risk_value"), None))
    return found


def _node_pointers(root: dict, root_ptr: tuple):
    """Yield (pointer, node) for every attack-tree node, depth first."""
    yield root_ptr, root
    for i, child in enumerate(root.get("children", [])):
        yield from _node_pointers(child, (*root_ptr, "children", i))


def _get(doc, ptr):
    for step in ptr:
        doc = doc[step]
    return doc

