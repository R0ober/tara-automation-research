"""One module per injection operator.

Each operator deep-copies the baseline, edits one site, and returns a
Candidate with a hand-written expected violation set, or a Skip with a
reason. Operators never call validate.violations().
"""

from __future__ import annotations

from ..sites import Site
from . import c1, c3, c4
from .base import Candidate, Context, Skip, make_context, site_rng

APPLY = {
    "C1a": c1.apply_c1a,
    "C1b": c1.apply_c1b,
    "C3": c3.apply,
    "C4": c4.apply,
}


def apply(ctx: Context, site: Site, seed: int) -> Candidate | Skip:
    return APPLY[site.operator](ctx, site, site_rng(seed, site))


__all__ = ["APPLY", "Candidate", "Context", "Skip", "apply", "make_context", "site_rng"]
