"""ID indexes of the item definition and the TARA, used by the injector.

The validator does not use this module; it has its own ID walker so that a
bug here cannot hide a defect from validation.
"""

from __future__ import annotations

ITEM_KINDS = ("item", "function", "component", "instance", "connection",
              "interface", "asset", "damage", "actor")
TARA_KINDS = ("scenario", "node", "goal", "requirement")


def item_definition_ids(item: dict) -> dict[str, set[str]]:
    """IDs defined by the item definition, by kind.

    Component `interfaces` lists and connection `entry_points` only refer to
    the `interfaces` registry; they do not define interface IDs.
    """
    ids: dict[str, set[str]] = {k: set() for k in ITEM_KINDS}
    meta = item.get("item_definition", {})
    if meta.get("item_id"):
        ids["item"].add(meta["item_id"])
    ids["function"] |= {f["function_id"] for f in meta.get("functions", [])}
    for c in item["components"]:
        ids["component"].add(c["component_id"])
        ids["instance"] |= {i["instance_id"] for i in c.get("instances", [])}
    ids["connection"] |= {c["connection_id"] for c in item["connections"]}
    ids["interface"] |= {i["interface_id"] for i in item.get("interfaces", [])}
    for a in item["assets"]:
        ids["asset"].add(a["asset_id"])
        ids["damage"] |= {d["damage_id"] for d in a["damage_scenarios"]}
    ids["actor"] |= {x["actor_id"] for x in item.get("external_actors", [])}
    return ids


def tara_internal_ids(tara: dict) -> dict[str, set[str]]:
    """IDs defined inside the TARA, by kind."""
    ids: dict[str, set[str]] = {k: set() for k in TARA_KINDS}
    for s in tara["threat_scenarios_and_attack_trees"]:
        ids["scenario"].add(s["threat_scenario_id"])
        ids["node"] |= {n["node_id"] for n in iter_nodes(s["attack_tree"])}
        treatment = s.get("proposed_risk_treatment") or {}
        ids["goal"] |= {g["goal_id"] for g in treatment.get("cybersecurity_goals", [])}
        ids["requirement"] |= {r["requirement_id"]
                               for r in treatment.get("cybersecurity_requirements", [])}
    return ids


def all_ids(item: dict, tara: dict) -> set[str]:
    """Every ID of any kind defined in either document."""
    out: set[str] = set()
    for group in (item_definition_ids(item), tara_internal_ids(tara)):
        for ids in group.values():
            out |= ids
    return out


def iter_nodes(node: dict):
    """Yield an attack-tree node and all its descendants, depth first."""
    yield node
    for child in node.get("children", []):
        yield from iter_nodes(child)


def interface_connection(item: dict) -> dict[str, str | None]:
    """Interface ID -> connection ID from the registry (None for debug ports)."""
    return {i["interface_id"]: i.get("connection_id") for i in item.get("interfaces", [])}


def interface_components(item: dict) -> dict[str, list[str]]:
    """Interface ID -> endpoint component IDs from the registry, in file order."""
    return {i["interface_id"]: list(i.get("endpoints", [])) for i in item.get("interfaces", [])}


def connection_components(item: dict) -> dict[str, list[str]]:
    """Connection ID -> component IDs on it (source, target, adjacent), in file order.

    External actors such as EXTERNAL_ATTACKER_SURFACE are excluded.
    """
    actors = {x["actor_id"] for x in item.get("external_actors", [])}
    out: dict[str, list[str]] = {}
    for c in item["connections"]:
        ends = [c.get("source_component"), c.get("target_component"),
                *c.get("adjacent_components", [])]
        out[c["connection_id"]] = list(dict.fromkeys(
            e for e in ends if isinstance(e, str) and e not in actors))
    return out
