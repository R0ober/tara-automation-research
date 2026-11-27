from tara_verification.injection.index import iter_nodes
from tara_verification.injection.known_issues import (
    INTENTIONAL_NULLS, KNOWN_ISSUES, KNOWN_VIOLATIONS,
)


def resolve(tara, object_id, field):
    """Minimal test-only resolver for the entries in known_issues."""
    for s in tara["threat_scenarios_and_attack_trees"]:
        if s["threat_scenario_id"] == object_id:
            prefix = "traceability_and_risk_summary."
            if field.startswith(prefix):
                row = next(r for r in tara["traceability_and_risk_summary"]
                           if r["threat_scenario_id"] == object_id)
                return row[field[len(prefix):]]
            obj = s
            for part in field.split("."):
                obj = obj[part]
            return obj
        for n in iter_nodes(s["attack_tree"]):
            if n["node_id"] == object_id:
                return n[field]
    raise KeyError(object_id)


def test_issue_codes_unique():
    codes = [c for c, _, _ in KNOWN_ISSUES]
    assert codes == sorted(set(codes))


def test_b1_still_present(bbw):
    (rule, obj, field), = KNOWN_VIOLATIONS["bbw"]
    assert rule == "R-REF"
    assert resolve(bbw.tara, obj, field) == "CONN-BRK-01"


def test_intentional_nulls_are_null(baseline):
    for system, entries in INTENTIONAL_NULLS.items():
        for obj, field in entries:
            assert resolve(baseline[system].tara, obj, field) is None, (system, obj, field)
