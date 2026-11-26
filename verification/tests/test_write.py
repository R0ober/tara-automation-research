import json
from dataclasses import replace

import pytest

from tara_verification.injection.load import BASELINE_REV, canonical
from tara_verification.injection.operators import Candidate, apply, make_context
from tara_verification.injection.sites import enumerate_sites
from tara_verification.injection.write import (
    DatasetError, assign_case_ids, case_id_of, prepare_out, write_dataset,
)

TS = "TS-BRK-01"


@pytest.fixture(scope="module")
def candidates(bbw):
    ctx = make_context(bbw.tara, bbw.item)
    return [r for r in (apply(ctx, s, 295) for s in enumerate_sites(bbw.tara, [TS], ["C3"]))
            if isinstance(r, Candidate)]


def test_case_id_is_content_hash(candidates):
    cases, dups = assign_case_ids(candidates)
    assert dups == [] and len(cases) == 6
    for case in cases:
        assert case.case_id == case_id_of(canonical(case.candidate.mutant))
        assert len(case.case_id) == 8


def test_duplicate_content_is_dropped(candidates):
    cases, dups = assign_case_ids([candidates[0], candidates[0]])
    assert len(cases) == 1 and len(dups) == 1
    assert dups[0].stage == "duplicate" and "same content as" in dups[0].reasons[0]


def test_hash_collision_stops(candidates, monkeypatch):
    import tara_verification.injection.write as write
    monkeypatch.setattr(write, "case_id_of", lambda text: "c-000000")
    with pytest.raises(DatasetError, match="collision"):
        write.assign_case_ids(candidates[:2])


def test_layout(tmp_path, bbw, candidates):
    out = tmp_path / "v0"
    prepare_out(out, overwrite=False)
    cases, _ = assign_case_ids(candidates)
    write_dataset(out, inputs=bbw, split="dev", seed=295, cases=cases, rejected=[],
                  manifest={"seed": 295})
    ids = sorted(c.case_id for c in cases)
    assert sorted(p.name for p in (out / "dev" / "cases").iterdir()) == ids
    assert sorted(p.stem for p in (out / "labels").iterdir()) == ids
    assert (out / "dev" / "context" / "item-definition.json").read_bytes() == bbw.item_bytes
    assert (out / "dev" / "context" / "functional-specification.txt").read_bytes() == bbw.spec_bytes
    assert not list((out / "dev").rglob("*label*"))
    label = json.loads((out / "labels" / f"{ids[0]}.json").read_text("utf-8"))
    assert label["base"] == {"system": "bbw", "tag": BASELINE_REV,
                             "tara_sha256": bbw.tara_sha256, "item_sha256": bbw.item_sha256}
    tara_text = (out / "dev" / "cases" / ids[0] / "tara.json").read_text("utf-8")
    assert case_id_of(tara_text) == ids[0]


def test_invalid_label_stops(tmp_path, bbw, candidates):
    bad = replace(candidates[0], defect=replace(candidates[0].defect, tier="X"))
    cases, _ = assign_case_ids([bad])
    out = tmp_path / "v0"
    prepare_out(out, overwrite=False)
    with pytest.raises(DatasetError, match="invalid label"):
        write_dataset(out, inputs=bbw, split="dev", seed=1, cases=cases, rejected=[], manifest={})


def test_prepare_out_protects_foreign_directories(tmp_path):
    out = tmp_path / "data"
    out.mkdir()
    (out / "keep.txt").write_text("x")
    with pytest.raises(DatasetError, match="not empty"):
        prepare_out(out, overwrite=False)
    with pytest.raises(DatasetError, match="no manifest.json"):
        prepare_out(out, overwrite=True)
    assert (out / "keep.txt").exists()
    (out / "manifest.json").write_text("{}")
    prepare_out(out, overwrite=True)
    assert list(out.iterdir()) == []
