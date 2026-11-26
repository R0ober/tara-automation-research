"""Known issues of the reference baseline (5ed3ae1).

Do not fix these in the injector. Baseline violations cancel out because the
validator only looks at violations(mutant) - violations(base).
"""

from __future__ import annotations

# (code, system, description), for reports and the manifest.
KNOWN_ISSUES = (
    ("B1", "bbw", "AT-BRK-02-B2.target_interface holds the connection ID CONN-BRK-01."),
    ("B2", "bbw", "CSR-BRK-02.1 and CSR-BRK-03.1 target_component disagrees with the text. "
                  "The IDs are valid, so M-tier rules do not report it."),
    ("B3", "bbw", "The name of INT-ETH-TSN-BRAKE contains an extra 'Redundant'."),
    ("B4", "all", "There is no structured attacker model (decision D2)."),
    ("B5", "all", "Feasibility bands and the risk matrix come from tara_metadata.methodology."),
    ("B6", "bbw", "TS-BRK-02 inherent risk is null on purpose."),
    ("B7", "ota-adas", "AT-OTA-03-B1.target_interface is null on purpose."),
    ("B8", "bbw", "Requirement numbers have gaps (CSR-BRK-01.2 and CSR-BRK-04.2 have no .1)."),
    ("B9", "bbw", "The BBW TARA version is still 1.0.0."),
)

# Exact baseline output of validate.violations(), as (rule, object_id, field).
KNOWN_VIOLATIONS: dict[str, frozenset[tuple[str, str, str]]] = {
    "bbw": frozenset({
        ("R-REF", "AT-BRK-02-B2", "target_interface"),  # B1
    }),
    "ota-adas": frozenset(),
}

# (object_id, field) pairs that hold an intentional null. No rule may report them.
INTENTIONAL_NULLS: dict[str, tuple[tuple[str, str], ...]] = {
    "bbw": (  # B6
        ("TS-BRK-02", "risk_determination.inherent_risk_value"),
        ("TS-BRK-02", "risk_determination.inherent_risk_level"),
        ("TS-BRK-02", "traceability_and_risk_summary.inherent_risk"),
    ),
    "ota-adas": (  # B7
        ("AT-OTA-03-B1", "target_interface"),
    ),
}
