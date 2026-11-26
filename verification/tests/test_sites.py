import pytest

from tara_verification.injection.index import iter_nodes
from tara_verification.injection.pointer import get_at
from tara_verification.injection.sites import OPERATORS, enumerate_sites

TS = "TS-BRK-01"


def sites(bbw, op, scenarios=(TS,)):
    return enumerate_sites(bbw.tara, list(scenarios), [op])


def coords(found):
    return [(s.object_id, s.field) for s in found]


def test_c1_sites(bbw):
    expected = [
        (TS, "targeted_asset.asset_id"),
        (TS, "targeted_asset.parent_component"),
        (TS, "targeted_asset.associated_connections"),
        (TS, "associated_damage_scenario.damage_id"),
        ("AT-BRK-01-B3", "target_component"),
        ("AT-BRK-01-B3", "target_interface"),
        ("CSR-BRK-01.2", "target_component"),
        (TS, "traceability_and_risk_summary.asset_id"),
        (TS, "traceability_and_risk_summary.damage_id"),
    ]
    assert coords(sites(bbw, "C1a")) == expected
    assert coords(sites(bbw, "C1b")) == expected
    assert [s.kind for s in sites(bbw, "C1a")] == [
        "asset", "component", "connection", "damage", "component", "interface",
        "component", "asset", "damage"]


def test_c3_sites(bbw):
    leaf = "AT-BRK-01-B3"
    assert coords(sites(bbw, "C3")) == [
        (leaf, "attack_potential.elapsed_time.score"),
        (leaf, "attack_potential.specialist_expertise.score"),
        (leaf, "attack_potential.knowledge_of_item.score"),
        (leaf, "attack_potential.window_of_opportunity.score"),
        (leaf, "attack_potential.equipment.score"),
        (leaf, "attack_potential.total_score"),
    ]


def test_c4_sites(bbw):
    assert coords(sites(bbw, "C4")) == [
        ("AT-BRK-01-ROOT", "aggregated_attack_feasibility"),
        ("AT-BRK-01-B3", "attack_potential.feasibility_rating"),
        (TS, "risk_determination.aggregated_attack_feasibility"),
        (TS, "risk_determination.inherent_risk_value"),
    ]


def test_pointers_resolve_and_fields_have_no_indices(baseline):
    for inputs in baseline.values():
        all_ts = [s["threat_scenario_id"] for s in inputs.tara["threat_scenarios_and_attack_trees"]]
        for site in enumerate_sites(inputs.tara, all_ts, list(OPERATORS)):
            assert get_at(inputs.tara, site.pointer) is not None
            assert not any(part.isdigit() for part in site.field.split("."))


def test_object_ids_exist(bbw):
    ids = {TS} | {n["node_id"] for n in iter_nodes(
        bbw.tara["threat_scenarios_and_attack_trees"][0]["attack_tree"])} | {"CSR-BRK-01.2"}
    assert {s.object_id for op in OPERATORS for s in sites(bbw, op)} <= ids


def test_null_and_unscored_are_skipped(baseline):
    bbw, ota = baseline["bbw"], baseline["ota-adas"]
    # B6: TS-BRK-02 risk is null; TS-BRK-04 is unscored.
    assert not any(s.field == "risk_determination.inherent_risk_value"
                   for s in sites(bbw, "C4", ["TS-BRK-02"]))
    assert sites(bbw, "C3", ["TS-BRK-04"]) == []
    # B7: the null interface of AT-OTA-03-B1 is not a C1 site.
    assert ("AT-OTA-03-B1", "target_interface") not in coords(
        enumerate_sites(ota.tara, ["TS-OTA-03"], ["C1a"]))


def test_unknown_inputs_fail(bbw):
    with pytest.raises(ValueError, match="unknown operators"):
        enumerate_sites(bbw.tara, [TS], ["C9"])
    with pytest.raises(ValueError, match="unknown scenarios"):
        enumerate_sites(bbw.tara, ["TS-BRK-99"], ["C3"])
