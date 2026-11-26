import pytest

from tara_verification.contract import check_label
from tara_verification.injection.operators import Candidate, Skip, apply, make_context
from tara_verification.injection.operators.c1 import dangling_ids
from tara_verification.injection.sites import enumerate_sites
from tara_verification.injection.validate import Violation, check_case

TS = "TS-BRK-01"
LEAF = "AT-BRK-01-B3"
ROOT = "AT-BRK-01-ROOT"
SUM = "traceability_and_risk_summary"
SEED = 295


@pytest.fixture(scope="module")
def results(bbw):
    ctx = make_context(bbw.tara, bbw.item)
    sites = enumerate_sites(bbw.tara, [TS], ["C1a", "C1b", "C3", "C4"])
    return [apply(ctx, s, SEED) for s in sites]


def by(results, op, field, object_id=None):
    (r,) = [r for r in results if r.site.operator == op and r.site.field == field
            and (object_id is None or r.site.object_id == object_id)]
    return r


def test_every_candidate_passes_validation(bbw, results):
    for r in results:
        if isinstance(r, Candidate):
            assert check_case(bbw.tara, r.mutant, bbw.item, [r.defect], set(r.expected),
                              bbw.spec_text) == [], r.site


def test_counts(results):
    made = {}
    for r in results:
        key = (r.site.operator, type(r).__name__)
        made[key] = made.get(key, 0) + 1
    assert made == {("C1a", "Candidate"): 9, ("C1b", "Candidate"): 4, ("C1b", "Skip"): 5,
                    ("C3", "Candidate"): 6, ("C4", "Candidate"): 4}


def test_c1b_skips_kinds_without_rule(results):
    skipped = {(r.site.kind, r.reason) for r in results if isinstance(r, Skip)}
    assert {k for k, _ in skipped} == {"asset", "connection", "damage"}
    assert all("no C1b combination rule" in reason for _, reason in skipped)


def test_c1a_ids_are_unused(bbw, results):
    ctx = make_context(bbw.tara, bbw.item)
    for r in results:
        if r.site.operator == "C1a":
            new = r.defect.edits[0].after
            assert new not in ctx.known_ids and new not in ctx.text
            assert new.rsplit("-", 1)[0] == r.defect.edits[0].before.rsplit("-", 1)[0]


def test_dangling_ids_change_one_character(bbw):
    ctx = make_context(bbw.tara, bbw.item)
    ids = dangling_ids("COMP-BPSU", ctx)
    assert "COMP-BPCU" in ids and "COMP-BPSU" not in ids
    assert all(sum(a != b for a, b in zip(x, "COMP-BPSU")) == 1 for x in ids)


def test_c1b_combinations(results):
    assert by(results, "C1b", "target_interface").defect.edits[0].after == \
        "INT-SWD-HEADER (COMP-BPSU)"
    for obj in (TS, LEAF, "CSR-BRK-01.2"):
        field = "targeted_asset.parent_component" if obj == TS else "target_component"
        after = by(results, "C1b", field, obj).defect.edits[0].after
        assert after in ("COMP-BPSU / COMP-VDCM", "COMP-BPSU / COMP-RIC")


def test_expected_c1(results):
    assert by(results, "C1a", "targeted_asset.asset_id").expected == {
        Violation("R-REF", TS, "targeted_asset.asset_id"),
        Violation("R-SUMMARY", TS, f"{SUM}.asset_id")}
    assert by(results, "C1a", f"{SUM}.damage_id").expected == {
        Violation("R-REF", TS, f"{SUM}.damage_id"), Violation("R-SUMMARY", TS, f"{SUM}.damage_id")}
    assert by(results, "C1a", "target_interface").expected == {
        Violation("R-REF", LEAF, "target_interface")}


def test_expected_c3(results):
    r = by(results, "C3", "attack_potential.equipment.score")
    assert r.expected == {Violation("R-SCORE", LEAF, "attack_potential.equipment.score"),
                          Violation("R-SUM", LEAF, "attack_potential.total_score")}
    r = by(results, "C3", "attack_potential.total_score")
    assert r.expected == {Violation("R-SUM", LEAF, "attack_potential.total_score"),
                          Violation("R-AGG", ROOT, "aggregated_attack_potential_score")}
    assert [(l.object_id, l.field) for l in r.defect.accepted_locations] == [
        (ROOT, "aggregated_attack_potential_score")]
    assert 14 <= r.defect.edits[0].after <= 19 and r.defect.edits[0].after != 15
    assert (r.defect.effect.band_changed, r.defect.effect.risk_changed) == (False, False)


def test_expected_c4(results):
    assert by(results, "C4", "attack_potential.feasibility_rating").expected == {
        Violation("R-BAND", LEAF, "attack_potential.feasibility_rating")}
    assert by(results, "C4", "aggregated_attack_feasibility").expected == {
        Violation("R-BAND", ROOT, "aggregated_attack_feasibility"),
        Violation("R-AGG", TS, "risk_determination.aggregated_attack_feasibility")}
    rd = by(results, "C4", "risk_determination.aggregated_attack_feasibility")
    # Severe impact: every other band changes the risk from 4.
    assert rd.expected == {
        Violation("R-AGG", TS, "risk_determination.aggregated_attack_feasibility"),
        Violation("R-SUMMARY", TS, f"{SUM}.inherent_feasibility"),
        Violation("R-RISK", TS, "risk_determination.inherent_risk_value")}
    risk = by(results, "C4", "risk_determination.inherent_risk_value")
    assert risk.expected == {Violation("R-RISK", TS, "risk_determination.inherent_risk_value"),
                             Violation("R-SUMMARY", TS, f"{SUM}.inherent_risk")}
    (value, level) = risk.defect.edits
    assert value.after not in (4,) and level.after == f"{value.after} / 5"
    assert level.path.endswith("/risk_determination/inherent_risk_level")


def test_c3_factor_effect(bbw):
    # equipment 4 -> 0 gives total 11 (Medium) and risk 5 under Severe impact.
    ctx = make_context(bbw.tara, bbw.item)
    (site,) = [s for s in enumerate_sites(bbw.tara, [TS], ["C3"])
               if s.field == "attack_potential.equipment.score"]
    for seed in range(50):
        r = apply(ctx, site, seed)
        if r.defect.edits[0].after == 0:
            assert (r.defect.effect.band_changed, r.defect.effect.risk_changed) == (True, True)
            return
    pytest.fail("no seed picked score 0")


def test_labels_are_well_formed(results):
    from tara_verification.contract import Base, Label
    for r in results:
        if isinstance(r, Candidate):
            label = Label("c-000000", Base("bbw", "5ed3ae1", "0" * 64, "1" * 64), "dev",
                          "single", SEED, (r.defect,))
            assert check_label(label) == []
            assert not any(p.isdigit() for p in r.defect.location.field.split("."))


def test_same_seed_same_result(bbw):
    ctx = make_context(bbw.tara, bbw.item)
    sites = enumerate_sites(bbw.tara, [TS], ["C1a", "C3", "C4"])
    first = [apply(ctx, s, SEED).defect for s in sites]
    assert first == [apply(ctx, s, SEED).defect for s in sites]
    assert first != [apply(ctx, s, SEED + 1).defect for s in sites]


def test_operators_do_not_touch_baseline(bbw):
    import copy
    before = copy.deepcopy(bbw.tara)
    ctx = make_context(bbw.tara, bbw.item)
    for s in enumerate_sites(bbw.tara, [TS], ["C1a", "C1b", "C3", "C4"]):
        apply(ctx, s, SEED)
    assert bbw.tara == before
