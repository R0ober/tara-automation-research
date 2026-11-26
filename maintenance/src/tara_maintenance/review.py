"""Create a TARA-preserving maintenance review overlay."""

from __future__ import annotations

from copy import deepcopy

from .baseline import InputError, JsonObject


def build_reviewed_tara(tara: JsonObject, report: JsonObject) -> JsonObject:
    """Return the original TARA plus review evidence, without changing analysis."""

    metadata = tara.get("tara_metadata", {})
    report_identity = report.get("tara", {})
    if (
        metadata.get("document_id") != report_identity.get("document_id")
        or metadata.get("item_id") != report_identity.get("item_id")
        or metadata.get("version") != report_identity.get("version")
    ):
        raise InputError("Maintenance report does not belong to the supplied TARA")
    if "maintenance_review" in tara:
        raise InputError("Input TARA already contains maintenance_review; refusing to stack it")

    reviewed = deepcopy(tara)
    reviewed["maintenance_review"] = {
        "schema_version": "1.0",
        "review_type": "maintenance_triage",
        "summary": deepcopy(report["summary"]),
        "recommendations": deepcopy(report["recommendations"]),
    }
    return reviewed
