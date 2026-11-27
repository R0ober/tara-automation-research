from tara_verification.injection.__main__ import run


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def build(repo, out, seed):
    run(repo=repo, system="bbw", scenarios=["TS-BRK-01"], operators=["C1a", "C1b", "C3", "C4"],
        seed=seed, out=out)
    return snapshot(out)


def test_deterministic(tmp_path, repo):
    first = build(repo, tmp_path / "a", 295)
    assert first == build(repo, tmp_path / "b", 295)
    assert first != build(repo, tmp_path / "c", 296)
