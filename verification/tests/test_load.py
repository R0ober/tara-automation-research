import json

import pytest

from tara_verification.injection.load import (
    BASELINE_REV, BASELINE_SHA256, InputError, canonical, load_inputs,
)


def test_baseline_hashes_match(baseline):
    for system, inputs in baseline.items():
        assert inputs.tara_sha256 == BASELINE_SHA256[system]["tara"]
        assert inputs.item_sha256 == BASELINE_SHA256[system]["item"]
        assert inputs.spec_sha256 == BASELINE_SHA256[system]["spec"]


def test_wrong_hash_fails(repo):
    with pytest.raises(InputError, match="does not match expected"):
        load_inputs(repo, "bbw", rev=BASELINE_REV, expected={"tara": "0" * 64})


def test_unknown_role_fails(repo):
    with pytest.raises(InputError, match="unknown input role"):
        load_inputs(repo, "bbw", rev=BASELINE_REV, expected={"other": "0" * 64})


def test_unknown_system_fails(repo):
    with pytest.raises(InputError, match="cannot read"):
        load_inputs(repo, "no-such-system", rev=BASELINE_REV)


def test_working_tree_read(tmp_path):
    for rel, text in (("shared/reference-tara/x/reference-tara.json", '{"a": 1}'),
                      ("shared/architecture/x/item-definition.json", '{"b": 2}'),
                      ("shared/architecture/x/functional-specification.txt", "spec")):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text(text, "utf-8")
    inputs = load_inputs(tmp_path, "x")
    assert inputs.rev is None
    assert (inputs.tara, inputs.item, inputs.spec_text) == ({"a": 1}, {"b": 2}, "spec")


def test_canonical_preserves_content_and_key_order(bbw):
    text = canonical(bbw.tara)
    assert text.endswith("}\n")
    assert json.loads(text) == bbw.tara
    assert list(json.loads(text)) == list(bbw.tara)
    assert canonical(json.loads(text)) == text


def test_canonical_keeps_non_ascii():
    assert canonical({"q": "client’s"}) == '{\n  "q": "client’s"\n}\n'
