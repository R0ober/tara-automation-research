import copy

import pytest

from tara_verification.injection.index import (
    all_ids, connection_components, interface_components, interface_connection,
    item_definition_ids, iter_nodes, tara_internal_ids,
)
from tara_verification.injection.pointer import from_rfc6901, get_at, set_at, to_rfc6901


def test_bbw_item_ids(bbw):
    ids = item_definition_ids(bbw.item)
    assert ids["item"] == {"AUTO-BBW-01"}
    assert ids["function"] == {"FUNC-BRK-01", "FUNC-BRK-02", "FUNC-BRK-03"}
    assert ids["component"] == {"COMP-BPSU", "COMP-VDCM", "COMP-RIC", "COMP-EBCM", "COMP-EMBA"}
    assert ids["instance"] == {"COMP-EMBA-FL", "COMP-EMBA-FR", "COMP-EMBA-RL", "COMP-EMBA-RR"}
    assert ids["connection"] == {"CONN-BRK-01", "CONN-BRK-02", "CONN-BRK-03", "CONN-BRK-04"}
    assert ids["interface"] == {"INT-BLE-DIAG", "INT-OBD2-CAN", "INT-CAN-CHASSIS",
                                "INT-ETH-TSN-BRAKE", "INT-CANFD-ACTUATOR", "INT-SWD-HEADER"}
    assert ids["asset"] == {f"ASSET-BRK-0{i}" for i in range(1, 5)}
    assert ids["damage"] == {f"DS-BRK-0{i}" for i in range(1, 5)}
    assert ids["actor"] == {"EXTERNAL_ATTACKER_SURFACE"}


def test_bbw_tara_ids(bbw):
    ids = tara_internal_ids(bbw.tara)
    assert ids["scenario"] == {f"TS-BRK-0{i}" for i in range(1, 5)}
    assert {"AT-BRK-01-ROOT", "AT-BRK-01-B3", "AT-BRK-03-B2"} <= ids["node"]
    assert len(ids["node"]) == 9
    assert ids["goal"] == {f"CG-BRK-0{i}" for i in range(1, 5)}
    assert "CSR-BRK-01.2" in ids["requirement"] and "CSR-BRK-01.1" not in ids["requirement"]


def test_kinds_do_not_overlap(baseline):
    for inputs in baseline.values():
        groups = [*item_definition_ids(inputs.item).values(),
                  *tara_internal_ids(inputs.tara).values()]
        assert sum(len(g) for g in groups) == len(all_ids(inputs.item, inputs.tara))


def test_ota_index_builds(baseline):
    ota = baseline["ota-adas"]
    assert item_definition_ids(ota.item)["item"] == {"AUTO-OTA-ADAS-01"}
    assert len(tara_internal_ids(ota.tara)["scenario"]) == 3


def test_iter_nodes_includes_root(bbw):
    tree = bbw.tara["threat_scenarios_and_attack_trees"][2]["attack_tree"]
    assert [n["node_id"] for n in iter_nodes(tree)] == [
        "AT-BRK-03-ROOT", "AT-BRK-03-B1", "AT-BRK-03-B2"]


def test_c1b_partner_maps(bbw):
    assert interface_connection(bbw.item)["INT-SWD-HEADER"] is None
    assert interface_connection(bbw.item)["INT-CANFD-ACTUATOR"] == "CONN-BRK-04"
    assert interface_components(bbw.item)["INT-SWD-HEADER"] == ["COMP-BPSU"]
    conns = connection_components(bbw.item)
    assert conns["CONN-BRK-01"] == ["COMP-VDCM"]
    assert conns["CONN-BRK-02"][:2] == ["COMP-BPSU", "COMP-VDCM"]


def test_pointer_round_trip(bbw):
    doc = copy.deepcopy(bbw.tara)
    ptr = ("threat_scenarios_and_attack_trees", 0, "attack_tree", "children", 0,
           "attack_potential", "equipment", "score")
    text = to_rfc6901(ptr)
    assert text == "/threat_scenarios_and_attack_trees/0/attack_tree/children/0/attack_potential/equipment/score"
    assert from_rfc6901(text, doc) == ptr
    assert get_at(doc, ptr) == 4
    set_at(doc, ptr, 7)
    assert get_at(doc, ptr) == 7
    assert get_at(bbw.tara, ptr) == 4


def test_pointer_escapes():
    doc = {"a/b": {"~c": 1}}
    assert to_rfc6901(("a/b", "~c")) == "/a~1b/~0c"
    assert from_rfc6901("/a~1b/~0c", doc) == ("a/b", "~c")
    with pytest.raises(ValueError):
        set_at(doc, (), 1)
