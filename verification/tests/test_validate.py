import copy
from dataclasses import replace

import pytest

from tara_verification.contract import Defect, Edit, Effect, Evidence, Location
from tara_verification.injection.known_issues import INTENTIONAL_NULLS, KNOWN_VIOLATIONS
from tara_verification.injection.load import canonical
from tara_verification.injection.validate import (
    TRACE_RE, Violation, changed_pointers, check_case, violations,
)

TS = "TS-BRK-01"
LEAF = "AT-BRK-01-B3"
ROOT = "AT-BRK-01-ROOT"
SUM = "traceability_and_risk_summary"
S0 = ("threat_scenarios_and_attack_trees", 0)
LEAF_PTR = (*S0, "attack_tree", "children", 0)
AP = (*LEAF_PTR, "attack_potential")
RD = (*S0, "risk_determination")


def ptr_text(path):
    return "".join(f"/{p}" for p in path)


def mutate(tara, *changes):
    doc = copy.deepcopy(tara)
    for path, value in changes:
        obj = doc
        for step in path[:-1]:
            obj = obj[step]
        obj[path[-1]] = value
    return doc


def new_violations(bbw, *changes):
    return violations(mutate(bbw.tara, *changes), bbw.item) - violations(bbw.tara, bbw.item)


def V(rule, obj, field):
    return Violation(rule, obj, field)


# --- baseline ---------------------------------------------------------------

@pytest.mark.parametrize("system", ["bbw", "ota-adas"])
def test_baseline_clean(baseline, system):
    inputs = baseline[system]
    assert violations(inputs.tara, inputs.item) == KNOWN_VIOLATIONS[system]


@pytest.mark.parametrize("system", ["bbw", "ota-adas"])
def test_null_not_flagged(baseline, system):
    inputs = baseline[system]
    reported = {(v.object_id, v.field) for v in violations(inputs.tara, inputs.item)}
    for entry in INTENTIONAL_NULLS[system]:
        assert entry not in reported


def test_unscored_leaf_is_not_flagged(bbw):
    s = bbw.tara["threat_scenarios_and_attack_trees"][3]
    assert s["attack_tree"]["children"][0]["attack_potential"] is None
    reported = {v.object_id for v in violations(bbw.tara, bbw.item)}
    assert not reported & {"TS-BRK-04", "AT-BRK-04-ROOT", "AT-BRK-04-B1"}


def test_trace_regex_silent_on_baseline(baseline):
    for inputs in baseline.values():
        text = canonical(inputs.tara) + inputs.item_bytes.decode("utf-8") + inputs.spec_text
        assert TRACE_RE.findall(text) == []


@pytest.mark.parametrize("text", ["MUT-1", "mutated value", "injected", "C1a", "C3", "U6",
                                  "I1", "R-SUM", "d1", "defect_id", "case_id"])
def test_trace_regex_hits(text):
    assert TRACE_RE.search(f"The {text} here.")


@pytest.mark.parametrize("text", ["mutual", "I2C bus", "CRC-8", "COMP-BPSU", "1d", "ASIL-D"])
def test_trace_regex_ignores(text):
    assert not TRACE_RE.search(f"The {text} here.")


# --- one counterexample per rule -------------------------------------------

def test_rule_ref_dangling(bbw):
    assert new_violations(bbw, ((*LEAF_PTR, "target_component"), "COMP-BPCU")) == {
        V("R-REF", LEAF, "target_component")}


def test_rule_ref_wrong_kind(bbw):
    assert new_violations(bbw, ((*LEAF_PTR, "target_interface"), "CONN-BRK-02")) == {
        V("R-REF", LEAF, "target_interface")}


def test_rule_ref_not_single_id(bbw):
    assert new_violations(bbw, ((*LEAF_PTR, "target_interface"), "INT-SWD-HEADER (COMP-BPSU)")) == {
        V("R-REF", LEAF, "target_interface")}


def test_rule_ref_connection_list(bbw):
    path = (*S0, "targeted_asset", "associated_connections")
    assert new_violations(bbw, (path, ["CONN-BRK-02 / CONN-BRK-03"])) == {
        V("R-REF", TS, "targeted_asset.associated_connections")}


def test_rule_ref_asset_also_breaks_summary(bbw):
    assert new_violations(bbw, ((*S0, "targeted_asset", "asset_id"), "ASSET-BRK-09")) == {
        V("R-REF", TS, "targeted_asset.asset_id"), V("R-SUMMARY", TS, f"{SUM}.asset_id")}


def test_rule_ref_in_summary_row(bbw):
    assert new_violations(bbw, ((SUM, 0, "damage_id"), "DS-BRK-09")) == {
        V("R-REF", TS, f"{SUM}.damage_id"), V("R-SUMMARY", TS, f"{SUM}.damage_id")}


def test_rule_ref_requirement(bbw):
    path = (*S0, "proposed_risk_treatment", "cybersecurity_requirements", 0, "target_component")
    assert new_violations(bbw, (path, "COMP-BPSU / COMP-VDCM")) == {
        V("R-REF", "CSR-BRK-01.2", "target_component")}


def test_rule_score(bbw):
    assert new_violations(bbw, ((*AP, "equipment", "score"), 7)) == {
        V("R-SCORE", LEAF, "attack_potential.equipment.score"),
        V("R-SUM", LEAF, "attack_potential.total_score")}


def test_rule_sum(bbw):
    assert new_violations(bbw, ((*AP, "total_score"), 16)) == {
        V("R-SUM", LEAF, "attack_potential.total_score"),
        V("R-AGG", ROOT, "aggregated_attack_potential_score")}


def test_rule_band_leaf(bbw):
    assert new_violations(bbw, ((*AP, "feasibility_rating"), "High")) == {
        V("R-BAND", LEAF, "attack_potential.feasibility_rating")}


def test_rule_band_root(bbw):
    path = (*S0, "attack_tree", "aggregated_attack_feasibility")
    assert new_violations(bbw, (path, "Medium")) == {
        V("R-BAND", ROOT, "aggregated_attack_feasibility"),
        V("R-AGG", TS, "risk_determination.aggregated_attack_feasibility")}


def test_rule_agg_root_score(bbw):
    path = (*S0, "attack_tree", "aggregated_attack_potential_score")
    assert new_violations(bbw, (path, 14)) == {
        V("R-AGG", ROOT, "aggregated_attack_potential_score"),
        V("R-AGG", TS, "risk_determination.minimum_attack_potential_score")}


def test_rule_agg_unknown_gate(bbw):
    assert V("R-AGG", ROOT, "aggregated_attack_potential_score") in new_violations(
        bbw, ((*S0, "attack_tree", "gate"), "XOR"))


def test_rule_agg_or_uses_lowest_child(bbw):
    # TS-BRK-03 has leaves 11 and 10; the root must keep 10.
    path = ("threat_scenarios_and_attack_trees", 2, "attack_tree",
            "aggregated_attack_potential_score")
    assert V("R-AGG", "AT-BRK-03-ROOT", "aggregated_attack_potential_score") in new_violations(
        bbw, (path, 11))


def test_rule_rd_feasibility(bbw):
    assert new_violations(bbw, ((*RD, "aggregated_attack_feasibility"), "Medium")) == {
        V("R-AGG", TS, "risk_determination.aggregated_attack_feasibility"),
        V("R-RISK", TS, "risk_determination.inherent_risk_value"),
        V("R-SUMMARY", TS, f"{SUM}.inherent_feasibility")}


def test_rule_risk_value_and_level(bbw):
    assert new_violations(bbw, ((*RD, "inherent_risk_value"), 3),
                          ((*RD, "inherent_risk_level"), "3 / 5")) == {
        V("R-RISK", TS, "risk_determination.inherent_risk_value"),
        V("R-SUMMARY", TS, f"{SUM}.inherent_risk")}


def test_rule_level(bbw):
    assert new_violations(bbw, ((*RD, "inherent_risk_value"), 5)) == {
        V("R-RISK", TS, "risk_determination.inherent_risk_value"),
        V("R-LEVEL", TS, "risk_determination.inherent_risk_level")}


def test_rule_impact(bbw):
    path = (*S0, "associated_damage_scenario", "impact_ratings", "overall_impact_rating")
    assert new_violations(bbw, (path, "Major")) == {
        V("R-IMPACT", TS, "associated_damage_scenario.impact_ratings.overall_impact_rating"),
        V("R-IMPACT", TS, "risk_determination.overall_impact_rating")}


def test_rule_summary(bbw):
    assert new_violations(bbw, ((SUM, 0, "inherent_impact"), "Major")) == {
        V("R-SUMMARY", TS, f"{SUM}.inherent_impact")}


def test_rule_summary_feasibility_score(bbw):
    assert new_violations(bbw, ((SUM, 0, "inherent_feasibility"),
                                "Low (Min Attack Potential = 16)")) == {
        V("R-SUMMARY", TS, f"{SUM}.inherent_feasibility")}


def test_rule_summary_band_only_format_accepted(bbw):
    assert new_violations(bbw, ((SUM, 0, "inherent_feasibility"), "Low")) == set()


def test_band_comes_from_methodology(bbw):
    # Moving the Low band to start at 16 makes the unchanged score 15 Medium.
    mapping = {"0-9": "High", "10-15": "Medium", "16-19": "Low", "20-24": "Very Low",
               ">=25": "Very Low"}
    path = ("tara_metadata", "methodology", "feasibility_mapping")
    assert {V("R-BAND", LEAF, "attack_potential.feasibility_rating"),
            V("R-BAND", ROOT, "aggregated_attack_feasibility")} <= new_violations(
        bbw, (path, mapping))


# --- check_case -------------------------------------------------------------

def c3_case(bbw, new_score=7, before=4):
    mutant = mutate(bbw.tara, ((*AP, "equipment", "score"), new_score))
    defect = Defect(
        defect_id="d1", category="contradiction", operator="C3", tier="M",
        origin="synthetic", policy="local",
        location=Location(TS, LEAF, "attack_potential.equipment.score"),
        accepted_locations=(),
        evidence=(Evidence("tara", LEAF, "attack_potential.equipment.label", "Specialized"),),
        effect=Effect(False, False),
        edits=(Edit(ptr_text((*AP, "equipment", "score")), before, new_score),),
    )
    expected = {V("R-SCORE", LEAF, "attack_potential.equipment.score"),
                V("R-SUM", LEAF, "attack_potential.total_score")}
    return mutant, defect, expected


def test_check_case_accepts_valid_case(bbw):
    mutant, defect, expected = c3_case(bbw)
    assert check_case(bbw.tara, mutant, bbw.item, [defect], expected) == []


def test_rejects_undeclared_edit(bbw):
    mutant, defect, expected = c3_case(bbw)
    mutant = mutate(mutant, ((*LEAF_PTR, "title"), "Other title"))
    assert any("changed pointers differ" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], expected))


def test_rejects_wrong_before(bbw):
    mutant, defect, expected = c3_case(bbw, before=5)
    assert any("'before' does not match" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], expected))


def test_rejects_unexpected_violations(bbw):
    mutant, defect, expected = c3_case(bbw)
    problems = check_case(bbw.tara, mutant, bbw.item, [defect],
                          {V("R-SCORE", LEAF, "attack_potential.equipment.score")})
    assert any("new violations differ from expected" in p for p in problems)


def test_rejects_equivalent_mutant(bbw):
    path = (*LEAF_PTR, "technical_detail")
    mutant = mutate(bbw.tara, (path, "Physical access to the pedal board is required."))
    _, defect, _ = c3_case(bbw)
    defect = replace(defect, edits=(Edit(ptr_text(path), bbw.tara["threat_scenarios_and_attack_trees"][0]
                                         ["attack_tree"]["children"][0]["technical_detail"],
                                         "Physical access to the pedal board is required."),))
    assert any("equivalent mutant" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], set()))


def test_rejects_removed_baseline_violation(bbw):
    path = ("threat_scenarios_and_attack_trees", 1, "attack_tree", "children", 0,
            "target_interface")
    mutant = mutate(bbw.tara, (path, "INT-BLE-DIAG"), ((*AP, "equipment", "score"), 7))
    _, defect, expected = c3_case(bbw)
    defect = replace(defect, edits=(*defect.edits, Edit(ptr_text(path), "CONN-BRK-01",
                                                         "INT-BLE-DIAG")))
    assert any("remove baseline violations" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], expected))


def test_rejects_trace(bbw):
    path = (*LEAF_PTR, "technical_detail")
    mutant, defect, expected = c3_case(bbw)
    mutant = mutate(mutant, (path, "This value was injected."))
    defect = replace(defect, edits=(*defect.edits, Edit(ptr_text(path), bbw.tara[
        "threat_scenarios_and_attack_trees"][0]["attack_tree"]["children"][0]["technical_detail"],
        "This value was injected.")))
    assert any("injection traces" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], expected))


def test_rejects_missing_quote(bbw):
    mutant, defect, expected = c3_case(bbw)
    defect = replace(defect, evidence=(Evidence("tara", LEAF, "scoring_basis", "no such words"),))
    assert any("not found" in p
               for p in check_case(bbw.tara, mutant, bbw.item, [defect], expected))


def test_rejects_unresolvable_evidence_and_location(bbw):
    mutant, defect, expected = c3_case(bbw)
    defect = replace(defect,
                     location=Location(TS, "AT-BRK-01-B9", "attack_potential"),
                     evidence=(Evidence("item_definition", "COMP-NONE", "name", None),))
    problems = check_case(bbw.tara, mutant, bbw.item, [defect], expected)
    assert any("location" in p and "cannot be resolved" in p for p in problems)
    assert any("evidence" in p and "cannot be resolved" in p for p in problems)


def test_absent_evidence(bbw):
    mutant, defect, expected = c3_case(bbw)
    ok = replace(defect, evidence=(Evidence("item_definition", None, None, "COMP-BPCU", "absent"),))
    assert check_case(bbw.tara, mutant, bbw.item, [ok], expected) == []
    bad = replace(defect, evidence=(Evidence("item_definition", None, None, "COMP-BPSU", "absent"),))
    assert any("is defined" in p for p in check_case(bbw.tara, mutant, bbw.item, [bad], expected))


def test_summary_and_spec_evidence(bbw):
    mutant, defect, expected = c3_case(bbw)
    quote = bbw.spec_text.strip().splitlines()[0][:20]
    d = replace(defect, accepted_locations=(Location(TS, TS, f"{SUM}.inherent_risk"),),
                evidence=(Evidence("tara", TS, f"{SUM}.inherent_risk", "4 / 5"),
                          Evidence("functional_specification", None, None, quote)))
    assert check_case(bbw.tara, mutant, bbw.item, [d], expected, bbw.spec_text) == []


def test_changed_pointers_detects_key_reorder():
    assert changed_pointers({"a": 1, "b": 2}, {"b": 2, "a": 1}) == {""}
    assert changed_pointers({"a": [1, 2]}, {"a": [1, 3]}) == {"/a/1"}
    assert changed_pointers({"a": 1}, {"a": True}) == {"/a"}
