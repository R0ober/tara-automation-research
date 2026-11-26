import json

import pytest

from tara_verification.injection.__main__ import run
from tara_verification.injection.load import canonical
from tara_verification.injection.validate import TRACE_RE

LABEL_KEYS = ("defect_id", "accepted_locations", "evidence", "edits", "expected",
              "operator", "origin", "policy", "tier", "effect", "seed")


@pytest.fixture(scope="module")
def dataset(tmp_path_factory, repo):
    out = tmp_path_factory.mktemp("v0")
    run(repo=repo, system="bbw", scenarios=["TS-BRK-01"], operators=["C1a", "C1b", "C3", "C4"],
        seed=295, out=out)
    return out


def keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from keys(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from keys(v)


def test_no_label_leak(dataset, bbw):
    split = dataset / "dev"
    files = [p for p in split.rglob("*") if p.is_file()]
    assert files
    assert not any("label" in p.name for p in split.rglob("*"))
    baseline_keys = set(keys(bbw.tara))
    for path in files:
        text = path.read_text("utf-8")
        assert TRACE_RE.findall(text) == [], path
        if path.name == "tara.json":
            doc = json.loads(text)
            assert set(keys(doc)) == baseline_keys, path
            assert canonical(doc) == text, path
            assert list(doc) == list(bbw.tara)


def test_labels_only_in_labels_dir(dataset):
    label_files = list((dataset / "labels").glob("*.json"))
    cases = list((dataset / "dev" / "cases").iterdir())
    assert sorted(p.stem for p in label_files) == sorted(p.name for p in cases)
    for p in label_files:
        label = json.loads(p.read_text("utf-8"))
        assert set(LABEL_KEYS) - {"expected", "seed"} <= set(keys(label["defects"]))


def test_layout_does_not_reveal_edits(dataset, bbw):
    # Same writer for every case: line count changes only if an edit changes it.
    base_lines = canonical(bbw.tara).count("\n")
    for case in (dataset / "dev" / "cases").iterdir():
        assert (case / "tara.json").read_text("utf-8").count("\n") == base_lines
