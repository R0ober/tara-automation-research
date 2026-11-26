from pathlib import Path

import pytest

from tara_verification.injection.load import BASELINE_REV, BASELINE_SHA256, load_inputs

REPO = Path(__file__).resolve().parents[2]
SYSTEMS = tuple(BASELINE_SHA256)


@pytest.fixture(scope="session")
def repo():
    return REPO


@pytest.fixture(scope="session")
def baseline():
    """Inputs of every system at the pinned baseline revision, keyed by system."""
    return {s: load_inputs(REPO, s, rev=BASELINE_REV, expected=BASELINE_SHA256[s])
            for s in SYSTEMS}


@pytest.fixture(scope="session")
def bbw(baseline):
    return baseline["bbw"]
