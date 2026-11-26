"""Independent validation of injected cases.

This module must not share code with the rule-based reviewer or with the
shared item-definition fact extraction (D7), and it does not use index.py.
It has its own ID walker and reads every table from tara_metadata.methodology.

Each rule compares two adjacent values only, so one edit produces a small,
predictable set of new violations:

    R-REF      not a single ID of the required kind in the item definition
    R-SCORE    factor score does not match its label
    R-SUM      total score != sum of factors
    R-BAND     feasibility band does not match the score on the same node
    R-AGG      node score violates the OR/AND rule, or a risk_determination
               copy (score, feasibility) differs from the root
    R-RISK     risk value does not match the matrix lookup
    R-LEVEL    inherent_risk_level does not match inherent_risk_value
    R-IMPACT   overall impact is not the highest of the four, or the
               risk_determination copy differs from it
    R-SUMMARY  summary row disagrees with the detailed section

A null risk, score or interface means "not assessed" and is never reported.
"""

from __future__ import annotations

import json
import re
from typing import Any, NamedTuple

from ..contract import Defect, Evidence
from .load import canonical

SUMMARY = "traceability_and_risk_summary"
OVERALL = "overall_impact_rating"
COMPONENT_KINDS = ("component", "instance")

# Markers of this tool that must never appear in a case: the MUT marker,
# operator codes, rule names, defect IDs and label field names. Ordinary
# English terms such as "message injection" are allowed. Case-sensitive.
LABEL_FIELDS = ("defect_id", "accepted_locations", "expected_violations", "case_id",
                "band_changed", "risk_changed")
TRACE_RE = re.compile(
    r"\b(?:MUT\w*"
    r"|[CUI][1-8][ab]?"
    r"|R-[A-Z]+"
    r"|d[0-9]+"
    r"|" + "|".join(LABEL_FIELDS) + r")\b"
)

# BBW writes "Low (Min Attack Potential = 15)"; OTA/ADAS writes only "High".
_SUMMARY_FEASIBILITY_RE = re.compile(
    r"^(?P<band>[^()]+?)(?: \(Min Attack Potential = (?P<score>-?\d+)\))?$")
_RANGE_RE = re.compile(r"^\s*(?P<lo>-?\d+)\s*-\s*(?P<hi>-?\d+)\s*$")
_BOUND_RE = re.compile(r"^\s*(?P<op>>=|<=|>|<)\s*(?P<n>-?\d+)\s*$")


class Violation(NamedTuple):
    rule: str
    object_id: str
    field: str


# --- ID walker (independent of index.py) ------------------------------------

def _defined_item_ids(item: dict) -> dict[str, set[str]]:
    kinds: dict[str, set[str]] = {}

    def add(kind: str, value: Any) -> None:
        if isinstance(value, str):
            kinds.setdefault(kind, set()).add(value)

    meta = item.get("item_definition") or {}
    add("item", meta.get("item_id"))
    for f in meta.get("functions") or []:
        add("function", f.get("function_id"))
    for c in item.get("components") or []:
        add("component", c.get("component_id"))
        for i in c.get("instances") or []:
            add("instance", i.get("instance_id"))
    for c in item.get("connections") or []:
        add("connection", c.get("connection_id"))
    for i in item.get("interfaces") or []:
        add("interface", i.get("interface_id"))
    for a in item.get("assets") or []:
        add("asset", a.get("asset_id"))
        for d in a.get("damage_scenarios") or []:
            add("damage", d.get("damage_id"))
    for x in item.get("external_actors") or []:
        add("actor", x.get("actor_id"))
    return kinds


def _item_objects(item: dict) -> dict[str, dict]:
    objs: dict[str, dict] = {}
    meta = item.get("item_definition") or {}
    objs["item_definition"] = meta
    for f in meta.get("functions") or []:
        objs[f.get("function_id")] = f
    for c in item.get("components") or []:
        objs[c.get("component_id")] = c
        for i in c.get("instances") or []:
            objs[i.get("instance_id")] = i
    for c in item.get("connections") or []:
        objs[c.get("connection_id")] = c
    for i in item.get("interfaces") or []:
        objs[i.get("interface_id")] = i
    for a in item.get("assets") or []:
        objs[a.get("asset_id")] = a
        for d in a.get("damage_scenarios") or []:
            objs[d.get("damage_id")] = d
    for x in item.get("external_actors") or []:
        objs[x.get("actor_id")] = x
    return objs


def _nodes(node: Any):
    if not isinstance(node, dict):
        return
    yield node
    for child in node.get("children") or []:
        yield from _nodes(child)


def _tara_objects(tara: dict) -> dict[str, dict]:
    """Object ID -> object. Scenario IDs map to the scenario object."""
    objs: dict[str, dict] = {"tara_metadata": tara.get("tara_metadata") or {}}
    for s in tara.get("threat_scenarios_and_attack_trees") or []:
        objs[s.get("threat_scenario_id")] = s
        for n in _nodes(s.get("attack_tree")):
            objs[n.get("node_id")] = n
        treatment = s.get("proposed_risk_treatment") or {}
        for g in treatment.get("cybersecurity_goals") or []:
            objs[g.get("goal_id")] = g
        for r in treatment.get("cybersecurity_requirements") or []:
            objs[r.get("requirement_id")] = r
    objs.pop(None, None)
    return objs


def _summary_rows(tara: dict) -> dict[str, list[dict]]:
    rows: dict[str, list[dict]] = {}
    for r in tara.get(SUMMARY) or []:
        rows.setdefault(r.get("threat_scenario_id"), []).append(r)
    return rows


# --- methodology helpers ----------------------------------------------------

def _band(score: Any, mapping: dict[str, str]) -> str | None:
    """Feasibility band for a score, parsed from the methodology range keys."""
    if score is None:
        return None
    if not isinstance(score, int) or isinstance(score, bool):
        return "<invalid score>"
    for key, band in mapping.items():
        m = _RANGE_RE.match(key)
        if m and int(m["lo"]) <= score <= int(m["hi"]):
            return band
        m = _BOUND_RE.match(key)
        if m:
            n = int(m["n"])
            if {">=": score >= n, "<=": score <= n, ">": score > n, "<": score < n}[m["op"]]:
                return band
    return "<no band>"


def _risk_max(matrix: dict) -> int | None:
    values = [v for row in matrix.values() for v in row.values() if isinstance(v, int)]
    return max(values) if values else None


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


# --- rules ------------------------------------------------------------------

def violations(tara: dict, item: dict) -> set[Violation]:
    """Return every rule violation in a TARA as (rule, object_id, field)."""
    out: set[Violation] = set()
    meth = (tara.get("tara_metadata") or {}).get("methodology") or {}
    factors: dict[str, dict] = meth.get("attack_potential_parameters") or {}
    mapping: dict[str, str] = meth.get("feasibility_mapping") or {}
    matrix: dict[str, dict] = meth.get("risk_matrix") or {}
    levels: list[str] = list(meth.get("impact_levels") or [])
    risk_max = _risk_max(matrix)
    ids = _defined_item_ids(item)

    def ref(obj_id: str, field: str, value: Any, kinds: tuple[str, ...], nullable: bool = True):
        if value is None and nullable:
            return
        if not (isinstance(value, str) and any(value in ids.get(k, ()) for k in kinds)):
            out.add(Violation("R-REF", obj_id, field))

    meta = tara.get("tara_metadata") or {}
    ref("tara_metadata", "item_id", meta.get("item_id"), ("item",), nullable=False)

    scenarios = tara.get("threat_scenarios_and_attack_trees") or []
    for s in scenarios:
        ts = s.get("threat_scenario_id")
        asset = s.get("targeted_asset") or {}
        damage = s.get("associated_damage_scenario") or {}
        ref(ts, "targeted_asset.asset_id", asset.get("asset_id"), ("asset",), nullable=False)
        ref(ts, "targeted_asset.parent_component", asset.get("parent_component"), ("component",))
        conns = asset.get("associated_connections")
        if conns is not None and not (
                isinstance(conns, list)
                and all(isinstance(c, str) and c in ids.get("connection", ()) for c in conns)):
            out.add(Violation("R-REF", ts, "targeted_asset.associated_connections"))
        ref(ts, "associated_damage_scenario.damage_id", damage.get("damage_id"), ("damage",),
            nullable=False)

        tree = s.get("attack_tree") or {}
        for n in _nodes(tree):
            nid = n.get("node_id")
            if "target_component" in n:
                ref(nid, "target_component", n["target_component"], COMPONENT_KINDS)
            if "target_interface" in n:
                ref(nid, "target_interface", n["target_interface"], ("interface",))
            _check_scoring(n, factors, mapping, out)
            if n.get("children"):
                _check_aggregation(n, mapping, out)

        treatment = s.get("proposed_risk_treatment") or {}
        for r in treatment.get("cybersecurity_requirements") or []:
            ref(r.get("requirement_id"), "target_component", r.get("target_component"),
                COMPONENT_KINDS)

        rd = s.get("risk_determination") or {}
        _check_risk_determination(ts, tree, damage, rd, matrix, levels, risk_max, out)

    _check_summary(tara, scenarios, ids, out)
    return out


def _check_scoring(n: dict, factors: dict, mapping: dict, out: set[Violation]) -> None:
    ap = n.get("attack_potential")
    if ap is None:  # unscored, not an error
        return
    nid = n.get("node_id")
    if not isinstance(ap, dict):
        out.add(Violation("R-SCORE", nid, "attack_potential"))
        return
    scores = []
    for f, table in factors.items():
        entry = ap.get(f)
        label = entry.get("label") if isinstance(entry, dict) else None
        score = entry.get("score") if isinstance(entry, dict) else None
        if label not in table or score != table[label] or not _is_int(score):
            out.add(Violation("R-SCORE", nid, f"attack_potential.{f}.score"))
        scores.append(score)
    total = ap.get("total_score")
    if not (_is_int(total) and all(_is_int(x) for x in scores) and total == sum(scores)):
        out.add(Violation("R-SUM", nid, "attack_potential.total_score"))
    if ap.get("feasibility_rating") != _band(total, mapping):
        out.add(Violation("R-BAND", nid, "attack_potential.feasibility_rating"))


def _node_score(n: dict) -> Any:
    ap = n.get("attack_potential")
    if isinstance(ap, dict):
        return ap.get("total_score")
    if n.get("children"):
        return n.get("aggregated_attack_potential_score")
    return None


def _check_aggregation(n: dict, mapping: dict, out: set[Violation]) -> None:
    """OR: lowest score among scored children, null if none is scored.

    AND: the methodology scores the complete path once, so the node's own
    attack_potential total is the aggregate. Without it, only "all children
    unscored implies null" is checked.
    """
    nid = n.get("node_id")
    agg = n.get("aggregated_attack_potential_score")
    scored = [x for x in (_node_score(c) for c in n["children"]) if x is not None]
    gate = n.get("gate")
    if gate == "OR":
        expected = min(scored) if scored and all(_is_int(x) for x in scored) else (
            None if not scored else "<invalid>")
        ok = agg == expected
    elif gate == "AND":
        ap = n.get("attack_potential")
        if isinstance(ap, dict):
            ok = agg == ap.get("total_score")
        else:
            ok = agg is None if not scored else True
    else:
        ok = False
    if not ok:
        out.add(Violation("R-AGG", nid, "aggregated_attack_potential_score"))
    if n.get("aggregated_attack_feasibility") != _band(agg, mapping):
        out.add(Violation("R-BAND", nid, "aggregated_attack_feasibility"))


def _check_risk_determination(ts: str, tree: dict, damage: dict, rd: dict, matrix: dict,
                              levels: list[str], risk_max: int | None,
                              out: set[Violation]) -> None:
    if rd.get("minimum_attack_potential_score") != tree.get("aggregated_attack_potential_score"):
        out.add(Violation("R-AGG", ts, "risk_determination.minimum_attack_potential_score"))
    if rd.get("aggregated_attack_feasibility") != tree.get("aggregated_attack_feasibility"):
        out.add(Violation("R-AGG", ts, "risk_determination.aggregated_attack_feasibility"))

    ratings = damage.get("impact_ratings") or {}
    four = [v.get("rating") for k, v in ratings.items() if k != OVERALL and isinstance(v, dict)]
    if four and all(r in levels for r in four):
        highest = max(four, key=levels.index)
    else:
        highest = "<invalid ratings>"
    if ratings.get(OVERALL) != highest:
        out.add(Violation("R-IMPACT", ts, f"associated_damage_scenario.impact_ratings.{OVERALL}"))
    if rd.get(OVERALL) != ratings.get(OVERALL):
        out.add(Violation("R-IMPACT", ts, f"risk_determination.{OVERALL}"))

    value = rd.get("inherent_risk_value")
    if value is not None:  # a null risk is an open assessment (B6)
        row = matrix.get(rd.get(OVERALL))
        expected = row.get(rd.get("aggregated_attack_feasibility")) if isinstance(row, dict) else None
        if not _is_int(value) or value != expected:
            out.add(Violation("R-RISK", ts, "risk_determination.inherent_risk_value"))
    expected_level = None if value is None else f"{value} / {risk_max}"
    if rd.get("inherent_risk_level") != expected_level:
        out.add(Violation("R-LEVEL", ts, "risk_determination.inherent_risk_level"))


def _check_summary(tara: dict, scenarios: list, ids: dict, out: set[Violation]) -> None:
    rows = _summary_rows(tara)
    known = {s.get("threat_scenario_id") for s in scenarios}
    for ts in rows:
        if ts not in known or len(rows[ts]) != 1:
            out.add(Violation("R-SUMMARY", str(ts), SUMMARY))
    for s in scenarios:
        ts = s.get("threat_scenario_id")
        if len(rows.get(ts, [])) != 1:
            out.add(Violation("R-SUMMARY", ts, SUMMARY))
            continue
        row = rows[ts][0]
        rd = s.get("risk_determination") or {}
        treatment = s.get("proposed_risk_treatment") or {}

        def summary(field: str, ok: bool) -> None:
            if not ok:
                out.add(Violation("R-SUMMARY", ts, f"{SUMMARY}.{field}"))

        for field, kind in (("asset_id", "asset"), ("damage_id", "damage")):
            if not (isinstance(row.get(field), str) and row[field] in ids.get(kind, ())):
                out.add(Violation("R-REF", ts, f"{SUMMARY}.{field}"))
        summary("asset_id", row.get("asset_id") == (s.get("targeted_asset") or {}).get("asset_id"))
        summary("damage_id", row.get("damage_id")
                == (s.get("associated_damage_scenario") or {}).get("damage_id"))
        summary("inherent_impact", row.get("inherent_impact") == rd.get(OVERALL))
        band, score = _summary_feasibility(row.get("inherent_feasibility"))
        summary("inherent_feasibility",
                band == rd.get("aggregated_attack_feasibility")
                and (score is _NO_SCORE and band is not None
                     or score == rd.get("minimum_attack_potential_score")))
        summary("inherent_risk", row.get("inherent_risk") == rd.get("inherent_risk_level"))
        summary("residual_feasibility",
                row.get("residual_feasibility") == treatment.get("target_residual_feasibility"))
        summary("residual_risk",
                row.get("residual_risk") == treatment.get("target_residual_risk_level"))


_NO_SCORE = object()


def _summary_feasibility(text: Any) -> tuple:
    """(band, score); score is _NO_SCORE when the summary states only the band."""
    if text is None:
        return (None, None)
    m = _SUMMARY_FEASIBILITY_RE.match(text) if isinstance(text, str) else None
    if not m:
        return ("<unparsed>", text)
    return (m["band"], _NO_SCORE if m["score"] is None else int(m["score"]))


# --- case checks ------------------------------------------------------------

def changed_pointers(base: Any, mutant: Any, prefix: str = "") -> set[str]:
    """RFC 6901 pointers of every value that differs, including key-order changes."""
    if type(base) is not type(mutant):
        return {prefix}
    if isinstance(base, dict):
        if list(base) != list(mutant):
            if set(base) == set(mutant):
                return {prefix}  # reordered keys would leak through the layout
            out = {f"{prefix}/{_esc(k)}" for k in set(base) ^ set(mutant)}
            keys = [k for k in base if k in mutant]
        else:
            out, keys = set(), list(base)
        for k in keys:
            out |= changed_pointers(base[k], mutant[k], f"{prefix}/{_esc(k)}")
        return out
    if isinstance(base, list):
        if len(base) != len(mutant):
            return {prefix}
        out = set()
        for i, (b, m) in enumerate(zip(base, mutant)):
            out |= changed_pointers(b, m, f"{prefix}/{i}")
        return out
    return set() if base == mutant else {prefix}


def _esc(key: str) -> str:
    return str(key).replace("~", "~0").replace("/", "~1")


_MISSING = object()


def _resolve_pointer(doc: Any, pointer: str) -> Any:
    if pointer == "":
        return doc
    for raw in pointer[1:].split("/"):
        step = raw.replace("~1", "/").replace("~0", "~")
        try:
            doc = doc[int(step)] if isinstance(doc, list) else doc[step]
        except (KeyError, IndexError, ValueError, TypeError):
            return _MISSING
    return doc


def _resolve_field(tara_or_item: dict, objects: dict, object_id: str | None,
                   field: str | None) -> Any:
    if object_id is None:
        obj: Any = tara_or_item
    else:
        obj = objects.get(object_id, _MISSING)
        if obj is _MISSING:
            return _MISSING
    if field is None:
        return obj
    if field == SUMMARY or field.startswith(SUMMARY + "."):
        rows = _summary_rows(tara_or_item).get(object_id) or []
        if len(rows) != 1:
            return _MISSING
        obj, field = rows[0], field[len(SUMMARY) + 1:]
        if not field:
            return obj
    for part in field.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return _MISSING
        obj = obj[part]
    return obj


def _as_text(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)


def _check_evidence(e: Evidence, mutant: dict, item: dict, spec_text: str) -> str | None:
    """Return a problem with one evidence entry, or None."""
    where = f"evidence {e.document}:{e.object_id}:{e.field}"
    if e.document == "functional_specification":
        if e.relation != "quote" or not e.quote or e.quote not in spec_text:
            return f"{where}: quote not found in the functional specification"
        return None
    if e.document == "tara":
        doc, objects = mutant, _tara_objects(mutant)
        defined = set(objects) - {"tara_metadata"}
    elif e.document == "item_definition":
        doc, objects = item, _item_objects(item)
        defined = {i for kind in _defined_item_ids(item).values() for i in kind}
    else:
        return f"{where}: unknown document"
    if e.relation == "absent":
        if not e.quote:
            return f"{where}: absent evidence has no ID"
        if e.quote in defined:
            return f"{where}: ID {e.quote!r} is defined, but the label says it is absent"
        return None
    value = _resolve_field(doc, objects, e.object_id, e.field)
    if value is _MISSING:
        return f"{where}: cannot be resolved"
    if e.quote is not None and e.quote not in _as_text(value):
        return f"{where}: quote {e.quote!r} not found"
    return None


def check_case(base: dict, mutant: dict, item: dict, defects: list[Defect],
               expected: set[Violation], spec_text: str = "") -> list[str]:
    """Return the reasons to reject a case (empty if the case is accepted).

    expected must come from the hand-written expected_violations() of each
    operator, never from violations().
    """
    problems: list[str] = []

    declared = [e.path for d in defects for e in d.edits]
    changed = changed_pointers(base, mutant)
    if len(declared) != len(set(declared)):
        problems.append("declared edits contain duplicate paths")
    if changed != set(declared):
        problems.append("changed pointers differ from declared edits: "
                        f"undeclared {sorted(changed - set(declared))}, "
                        f"unchanged {sorted(set(declared) - changed)}")
    for d in defects:
        for e in d.edits:
            if _resolve_pointer(base, e.path) != e.before:
                problems.append(f"edit {e.path}: 'before' does not match the baseline")
            if _resolve_pointer(mutant, e.path) != e.after:
                problems.append(f"edit {e.path}: 'after' does not match the case")

    base_v, mutant_v = violations(base, item), violations(mutant, item)
    new, removed = mutant_v - base_v, base_v - mutant_v
    if not new:
        problems.append("the edits add no new violation (equivalent mutant)")
    elif new != set(expected):
        problems.append("new violations differ from expected: "
                        f"unexpected {sorted(new - set(expected))}, "
                        f"missing {sorted(set(expected) - new)}")
    if removed:
        problems.append(f"the edits remove baseline violations {sorted(removed)}")

    hits = sorted(set(m.group(0) for m in TRACE_RE.finditer(canonical(mutant))))
    if hits:
        problems.append(f"injection traces in the case: {hits}")

    objects = _tara_objects(mutant)
    for d in defects:
        for loc in (d.location, *d.accepted_locations):
            if loc.scenario_id not in objects or _resolve_field(
                    mutant, objects, loc.object_id, loc.field) is _MISSING:
                problems.append(f"location {loc.scenario_id}:{loc.object_id}:{loc.field} "
                                "cannot be resolved in the case")
        for e in d.evidence:
            problem = _check_evidence(e, mutant, item, spec_text)
            if problem:
                problems.append(problem)
    return problems
