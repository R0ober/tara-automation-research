"""Minimal CPE 2.3 product and numeric-version range matching."""

from __future__ import annotations

import re
from typing import Any

NUMERIC_VERSION = re.compile(r"\d+(?:\.\d+)*")
RANGE_FIELDS = (
    "version_start_including",
    "version_end_including",
    "version_start_excluding",
    "version_end_excluding",
)


def product_key(cpe: str) -> tuple[str, str, str] | None:
    """Return CPE part/vendor/product, or None for unsupported bindings."""

    fields = _split_unescaped(cpe)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None
    return (fields[2].casefold(), fields[3].casefold(), fields[4].casefold())


def cpe_version(cpe: str) -> str | None:
    fields = _split_unescaped(cpe)
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return None
    return fields[5]


def rule_matches_version(rule: dict[str, Any], installed_cpe: str) -> bool | None:
    """Return True/False, or None when a version cannot be compared safely."""

    installed_version = cpe_version(installed_cpe)
    rule_version = cpe_version(rule["cpe"])
    if installed_version is None or rule_version is None:
        return None
    if rule_version not in {"*", "-"} and not any(field in rule for field in RANGE_FIELDS):
        if installed_version in {"*", "-"}:
            return None
        return installed_version == rule_version
    if not any(field in rule for field in RANGE_FIELDS):
        return installed_version == "-" if rule_version == "-" else True
    if installed_version in {"*", "-"}:
        return None
    installed = _numeric_version(installed_version)
    if installed is None:
        return None

    comparisons = (
        ("version_start_including", lambda bound: installed >= bound),
        ("version_end_including", lambda bound: installed <= bound),
        ("version_start_excluding", lambda bound: installed > bound),
        ("version_end_excluding", lambda bound: installed < bound),
    )
    for field, comparison in comparisons:
        if field not in rule:
            continue
        bound = _numeric_version(str(rule[field]))
        if bound is None:
            return None
        if not comparison(bound):
            return False
    return True


def _numeric_version(value: str) -> tuple[int, ...] | None:
    if not NUMERIC_VERSION.fullmatch(value):
        return None
    parts = [int(part) for part in value.split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _split_unescaped(value: str) -> list[str]:
    fields = []
    current = []
    escaped = False
    for character in value:
        if escaped:
            current.extend(("\\", character))
            escaped = False
        elif character == "\\":
            escaped = True
        elif character == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(character)
    if escaped:
        current.append("\\")
    fields.append("".join(current))
    return fields
