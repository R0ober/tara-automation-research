import dataclasses
import json
from pathlib import Path

import pytest

from tara_verification.contract import (
    Base, Defect, Edit, Effect, Evidence, Finding, Label, Location,
    check_finding, check_label, to_dict,
)

SCHEMA_DIR = Path(__file__).parents[1] / "src/tara_verification/contract"


def schema(name):
    return json.loads((SCHEMA_DIR / name).read_text("utf-8"))


def make_label(**overrides):
    loc = Location("TS-BRK-01", "AT-BRK-01-B3", "attack_potential.equipment.score")
    defect = Defect(
        defect_id="d1", category="contradiction", operator="C3", tier="M",
        origin="synthetic", policy="local", location=loc,
        accepted_locations=(Location("TS-BRK-01", "AT-BRK-01-ROOT",
                                     "aggregated_attack_potential_score"),),
        evidence=(Evidence("tara", "AT-BRK-01-B3", "attack_potential.equipment.label",
                           "Specialized"),),
        effect=Effect(band_changed=False, risk_changed=False),
        edits=(Edit("/threat_scenarios_and_attack_trees/0/attack_tree/children/0"
                    "/attack_potential/equipment/score", 4, 7),),
    )
    fields = dict(case_id="c-7f3a91",
                  base=Base("bbw", "5ed3ae1", "0" * 64, "1" * 64),
                  split="v0", case_type="single", seed=295, defects=(defect,))
    fields.update(overrides)
    return Label(**fields)


def field_names(cls):
    return {f.name for f in dataclasses.fields(cls)}


@pytest.mark.parametrize("cls, props", [
    (Label, lambda s: s["properties"]),
    (Base, lambda s: s["properties"]["base"]["properties"]),
    (Defect, lambda s: s["$defs"]["defect"]["properties"]),
    (Location, lambda s: s["$defs"]["location"]["properties"]),
    (Evidence, lambda s: s["$defs"]["evidence"]["properties"]),
    (Effect, lambda s: s["$defs"]["defect"]["properties"]["effect"]["properties"]),
    (Edit, lambda s: s["$defs"]["defect"]["properties"]["edits"]["items"]["properties"]),
])
def test_label_fields_match_schema(cls, props):
    assert field_names(cls) == set(props(schema("label.schema.json")))


def test_finding_fields_match_schema():
    assert field_names(Finding) == set(schema("finding.schema.json")["properties"])


def test_label_round_trip():
    label = make_label()
    data = json.loads(json.dumps(to_dict(label)))
    assert Label.from_dict(data) == label


def test_finding_round_trip():
    finding = Finding("contradiction", Location("TS-BRK-01", "AT-BRK-01-B3", "scoring_basis"),
                      "The rating disagrees with the basis.",
                      (Evidence("tara", "AT-BRK-01-B3", "scoring_basis", "proficient personnel"),))
    assert Finding.from_dict(json.loads(json.dumps(to_dict(finding)))) == finding
    assert check_finding(finding) == []


def test_valid_label_has_no_problems():
    assert check_label(make_label()) == []


def test_check_label_rejects_bad_values():
    label = make_label()
    bad = dataclasses.replace(label.defects[0], category="wrong", tier="X", edits=())
    problems = check_label(dataclasses.replace(label, case_type="other", defects=(bad, bad)))
    text = "\n".join(problems)
    for expected in ("unknown case_type", "duplicate defect_id", "unknown category",
                     "unknown tier", "no edits"):
        assert expected in text


def test_absent_evidence_needs_quote():
    label = make_label()
    d = dataclasses.replace(label.defects[0],
                            evidence=(Evidence("item_definition", None, None, None, "absent"),))
    assert any("absent evidence" in p for p in check_label(dataclasses.replace(label, defects=(d,))))
