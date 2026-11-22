"""Rule-based TARA maintenance baseline.

The baseline links vulnerability and component changes to the supplied item
architecture. It never treats missing impact information as evidence that a
change is irrelevant.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .cpe import product_key, rule_matches_version

JsonObject = dict[str, Any]
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


class InputError(ValueError):
    """Raised when an input document cannot be used by the baseline."""


@dataclass(frozen=True)
class AttackReference:
    """An attack-tree node relevant to a component or vulnerability."""

    scenario_id: str
    node_id: str
    title: str
    target_component: str | None
    vulnerability_reference: str | None

    def as_dict(self) -> JsonObject:
        result: JsonObject = {
            "threat_scenario_id": self.scenario_id,
            "node_id": self.node_id,
            "title": self.title,
        }
        if self.target_component:
            result["target_component"] = self.target_component
        if self.vulnerability_reference:
            result["vulnerability_reference"] = self.vulnerability_reference
        return result


def load_json(path: str | Path) -> JsonObject:
    """Load a JSON object and convert file/parse failures to ``InputError``."""

    source = Path(path)
    try:
        with source.open(encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InputError(f"Cannot load JSON from {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise InputError(f"JSON root in {source} must be an object")
    return value


def evaluate_changes(
    tara: JsonObject, architecture: JsonObject, changes: JsonObject
) -> JsonObject:
    """Evaluate a change document against a TARA and its item architecture."""

    return MaintenanceBaseline(tara, architecture).evaluate(changes)


class MaintenanceBaseline:
    """Index reference artifacts and produce deterministic review decisions."""

    def __init__(self, tara: JsonObject, architecture: JsonObject) -> None:
        if not isinstance(tara, dict) or not isinstance(architecture, dict):
            raise InputError("TARA and architecture roots must be objects")
        self.tara = tara
        self.architecture = architecture
        self._validate_item_identity()

        self._component_names: dict[str, str] = {}
        self._cpe_inventory: dict[str, list[JsonObject]] = defaultdict(list)
        self._cpe_products: dict[tuple[str, str, str], list[JsonObject]] = defaultdict(list)
        self._component_scenarios: dict[str, set[str]] = defaultdict(set)
        self._component_attacks: dict[str, list[AttackReference]] = defaultdict(list)
        self._cve_attacks: dict[str, list[AttackReference]] = defaultdict(list)
        self._index_architecture()
        self._index_tara()

    def evaluate(self, changes: JsonObject) -> JsonObject:
        """Return one recommendation per change, preserving input order."""

        if not isinstance(changes, dict) or not isinstance(changes.get("changes"), list):
            raise InputError("Change document must contain a 'changes' array")

        recommendations: list[JsonObject] = []
        seen_ids: set[str] = set()
        for position, raw_change in enumerate(changes["changes"]):
            if not isinstance(raw_change, dict):
                raise InputError(f"Change at index {position} must be an object")
            change = self._validate_change(raw_change, position)
            change_id = change["change_id"]
            if change_id in seen_ids:
                raise InputError(f"Duplicate change_id: {change_id}")
            seen_ids.add(change_id)
            if change["type"] == "vulnerability":
                recommendations.append(self._evaluate_vulnerability(change))
            else:
                recommendations.append(self._evaluate_component_change(change))

        counts = {
            decision: sum(item["decision"] == decision for item in recommendations)
            for decision in ("review_required", "no_review", "unresolved")
        }
        metadata = self.tara.get("tara_metadata", {})
        return {
            "schema_version": "1.0",
            "tara": {
                "document_id": metadata.get("document_id"),
                "version": metadata.get("version"),
                "item_id": metadata.get("item_id"),
            },
            "summary": {"total": len(recommendations), **counts},
            "recommendations": recommendations,
        }

    def _validate_item_identity(self) -> None:
        tara_item = self.tara.get("tara_metadata", {}).get("item_id")
        architecture_item = self.architecture.get("item_definition", {}).get("item_id")
        if tara_item and architecture_item and tara_item != architecture_item:
            raise InputError(
                f"TARA item_id {tara_item!r} does not match architecture "
                f"item_id {architecture_item!r}"
            )

    def _index_architecture(self) -> None:
        components = self.architecture.get("components", [])
        if not isinstance(components, list):
            raise InputError("Architecture 'components' must be an array")
        for component in components:
            if not isinstance(component, dict) or not component.get("component_id"):
                raise InputError("Each architecture component requires a component_id")
            component_id = component["component_id"]
            if component_id in self._component_names:
                raise InputError(f"Duplicate architecture component_id: {component_id}")
            self._component_names[component_id] = component.get("name", component_id)

            software_entries: list[tuple[str, JsonObject]] = []
            os_entry = component.get("os")
            if isinstance(os_entry, dict):
                software_entries.append(("operating_system", os_entry))
            hosted = component.get("hosted_software", [])
            if isinstance(hosted, list):
                software_entries.extend(
                    ("hosted_software", entry)
                    for entry in hosted
                    if isinstance(entry, dict)
                )
            for kind, software in software_entries:
                cpe = software.get("cpe")
                if not isinstance(cpe, str) or not cpe:
                    continue
                inventory_entry = {
                    "component_id": component_id,
                    "kind": kind,
                    "name": software.get("name"),
                    "version": software.get("version")
                    or software.get("kernel_version"),
                    "cpe": cpe,
                }
                self._cpe_inventory[cpe].append(inventory_entry)
                key = product_key(cpe)
                if key:
                    self._cpe_products[key].append(inventory_entry)

    def _index_tara(self) -> None:
        scenarios = self.tara.get("threat_scenarios_and_attack_trees", [])
        if not isinstance(scenarios, list):
            raise InputError("TARA 'threat_scenarios_and_attack_trees' must be an array")
        for scenario in scenarios:
            if not isinstance(scenario, dict):
                continue
            scenario_id = str(scenario.get("threat_scenario_id", ""))
            asset = scenario.get("targeted_asset", {})
            if isinstance(asset, dict) and asset.get("parent_component"):
                self._component_scenarios[asset["parent_component"]].add(scenario_id)
            root = scenario.get("attack_tree")
            if isinstance(root, dict):
                self._index_attack_node(root, scenario_id)

    def _index_attack_node(self, node: JsonObject, scenario_id: str) -> None:
        reference = AttackReference(
            scenario_id=scenario_id,
            node_id=str(node.get("node_id", "")),
            title=str(node.get("title", "")),
            target_component=node.get("target_component"),
            vulnerability_reference=node.get("vulnerability_reference"),
        )
        if reference.target_component:
            self._component_attacks[reference.target_component].append(reference)
        if reference.vulnerability_reference:
            for match in CVE_PATTERN.finditer(reference.vulnerability_reference):
                self._cve_attacks[match.group(0).upper()].append(reference)
        children = node.get("children", [])
        if isinstance(children, list):
            for child in children:
                if isinstance(child, dict):
                    self._index_attack_node(child, scenario_id)

    def _validate_change(self, change: JsonObject, position: int) -> JsonObject:
        for field in ("change_id", "type", "source"):
            if not isinstance(change.get(field), str) or not change[field].strip():
                raise InputError(
                    f"Change at index {position} requires a non-empty string '{field}'"
                )
        if "source_url" in change and not isinstance(change["source_url"], str):
            raise InputError(f"Change {change['change_id']}: source_url must be a string")

        change_type = change["type"]
        if change_type == "vulnerability":
            cve_id = change.get("cve_id")
            if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id.strip()):
                raise InputError(
                    f"Change {change['change_id']}: cve_id must be a valid CVE identifier"
                )
            normalized = dict(change)
            normalized["cve_id"] = cve_id.strip().upper()
            components = self._string_list(change, "affected_components")
            cpes = self._string_list(change, "affected_cpes")
            ranges = self._cpe_range_list(change)
            if not components and not cpes and not ranges:
                raise InputError(
                    f"Change {change['change_id']}: vulnerability requires "
                    "affected_components, affected_cpes, or affected_cpe_ranges"
                )
            normalized["affected_components"] = components
            normalized["affected_cpes"] = cpes
            normalized["affected_cpe_ranges"] = ranges
            return normalized

        if change_type == "component_change":
            if not isinstance(change.get("component_id"), str) or not change[
                "component_id"
            ].strip():
                raise InputError(
                    f"Change {change['change_id']}: component_change requires component_id"
                )
            if "before" not in change or "after" not in change:
                raise InputError(
                    f"Change {change['change_id']}: component_change requires before and after"
                )
            return change

        raise InputError(
            f"Change {change['change_id']}: unsupported type {change_type!r}; "
            "expected 'vulnerability' or 'component_change'"
        )

    @staticmethod
    def _string_list(change: JsonObject, field: str) -> list[str]:
        value = change.get(field, [])
        if not isinstance(value, list) or any(
            not isinstance(item, str) or not item.strip() for item in value
        ):
            raise InputError(f"Change {change['change_id']}: {field} must be a string array")
        return [item.strip() for item in value]

    @staticmethod
    def _cpe_range_list(change: JsonObject) -> list[JsonObject]:
        value = change.get("affected_cpe_ranges", [])
        if not isinstance(value, list):
            raise InputError(
                f"Change {change['change_id']}: affected_cpe_ranges must be an array"
            )
        for rule in value:
            if not isinstance(rule, dict) or not isinstance(rule.get("cpe"), str):
                raise InputError(
                    f"Change {change['change_id']}: each CPE range requires a cpe string"
                )
            for field in (
                "version_start_including",
                "version_end_including",
                "version_start_excluding",
                "version_end_excluding",
            ):
                if field in rule and not isinstance(rule[field], str):
                    raise InputError(
                        f"Change {change['change_id']}: {field} must be a string"
                    )
        return value

    def _evaluate_vulnerability(self, change: JsonObject) -> JsonObject:
        matched_components, matched_software, unknown, range_evidence = (
            self._match_vulnerability(change)
        )
        evidence = self._base_evidence(change)
        evidence["matched_components"] = [
            {
                "component_id": component_id,
                "name": self._component_names[component_id],
                "matched_by": matched_by,
            }
            for component_id, matched_by in sorted(matched_components.items())
        ]
        evidence["matched_software"] = matched_software
        evidence["matched_cpe_rules"] = range_evidence["matched"]
        evidence["excluded_software"] = range_evidence["excluded"]
        evidence["unresolved_identifiers"] = unknown
        evidence["related_threat_scenarios"] = self._related_scenarios(matched_components)
        evidence["related_attack_steps"] = self._related_attacks(matched_components)

        existing_references = self._deduplicate_references(
            self._cve_attacks.get(change["cve_id"], [])
        )
        if existing_references:
            evidence["existing_vulnerability_references"] = [
                reference.as_dict() for reference in existing_references
            ]

        if existing_references and range_evidence["excluded"]:
            decision = "review_required"
            rationale = (
                f"{change['cve_id']} is referenced by the TARA, but current version-range "
                "evidence excludes the installed software. Review the conflicting reference."
            )
        elif not matched_components:
            if range_evidence["excluded"]:
                decision = "no_review"
                rationale = (
                    "The installed same-product software version is outside all supplied "
                    "vulnerable ranges; no matching affected component was found."
                )
            else:
                decision = "unresolved"
                rationale = (
                    "No affected component or CPE rule could be linked to the reference "
                    "architecture; applicability to the item is unknown."
                )
        elif existing_references:
            decision = "no_review"
            rationale = (
                f"{change['cve_id']} is already referenced by the existing TARA; "
                "the baseline does not reassess severity or exploitability updates."
            )
        else:
            decision = "review_required"
            rationale = (
                f"{change['cve_id']} affects at least one component in the item and is "
                "not referenced by the existing TARA."
            )

        return {
            "change_id": change["change_id"],
            "change_type": change["type"],
            "vulnerability_id": change["cve_id"],
            "decision": decision,
            "rationale": rationale,
            "evidence": evidence,
        }

    def _match_vulnerability(
        self, change: JsonObject
    ) -> tuple[dict[str, list[str]], list[JsonObject], JsonObject, JsonObject]:
        matched: dict[str, set[str]] = defaultdict(set)
        matched_software: list[JsonObject] = []
        matched_rules: list[JsonObject] = []
        excluded_software: list[JsonObject] = []
        unknown_components = [
            component_id
            for component_id in change["affected_components"]
            if component_id not in self._component_names
        ]
        unknown_cpes: list[str] = []
        range_rules: dict[str, list[JsonObject]] = defaultdict(list)
        for rule in change["affected_cpe_ranges"]:
            range_rules[rule["cpe"]].append(rule)

        for component_id in change["affected_components"]:
            if component_id in self._component_names:
                matched[component_id].add("affected_components")
        for cpe in change["affected_cpes"]:
            exact_inventory = self._cpe_inventory.get(cpe, [])
            if exact_inventory:
                for software in exact_inventory:
                    matched[software["component_id"]].add("affected_cpes")
                    matched_software.append(software)
                continue

            candidates = self._cpe_products.get(product_key(cpe) or (), [])
            if not candidates:
                unknown_cpes.append(cpe)
                continue
            rules = range_rules.get(cpe) or [{"cpe": cpe}]
            cpe_has_unknown = False
            for software in candidates:
                outcomes = [rule_matches_version(rule, software["cpe"]) for rule in rules]
                positive_rules = [
                    rule for rule, outcome in zip(rules, outcomes, strict=True) if outcome is True
                ]
                if positive_rules:
                    matched[software["component_id"]].add("affected_cpe_ranges")
                    matched_software.append(software)
                    for rule in positive_rules:
                        matched_rules.append(
                            {
                                **rule,
                                "component_id": software["component_id"],
                                "installed_version": software["version"],
                            }
                        )
                elif any(outcome is None for outcome in outcomes):
                    cpe_has_unknown = True
                else:
                    for rule in rules:
                        excluded_software.append(
                            {
                                **rule,
                                "component_id": software["component_id"],
                                "software": software["name"],
                                "installed_version": software["version"],
                            }
                        )
            if cpe_has_unknown and not any(
                item["cpe"] == cpe for item in matched_rules
            ):
                unknown_cpes.append(cpe)

        unique_software = {
            (item["component_id"], item["cpe"], item["kind"]): item
            for item in matched_software
        }
        return (
            {key: sorted(value) for key, value in matched.items()},
            sorted(
                unique_software.values(),
                key=lambda item: (item["component_id"], item["cpe"], item["kind"]),
            ),
            {"components": unknown_components, "cpes": unknown_cpes},
            {"matched": matched_rules, "excluded": excluded_software},
        )

    def _evaluate_component_change(self, change: JsonObject) -> JsonObject:
        component_id = change["component_id"].strip()
        evidence = self._base_evidence(change)
        evidence["changed_fields"] = self._changed_fields(change["before"], change["after"])
        evidence["before"] = change["before"]
        evidence["after"] = change["after"]

        if component_id not in self._component_names:
            decision = "unresolved"
            rationale = (
                f"Component {component_id} is not present in the reference architecture; "
                "its relationship to the item is unknown."
            )
            evidence["related_threat_scenarios"] = []
            evidence["related_attack_steps"] = []
        else:
            evidence["component"] = {
                "component_id": component_id,
                "name": self._component_names[component_id],
            }
            evidence["related_threat_scenarios"] = self._related_scenarios(
                {component_id: []}
            )
            evidence["related_attack_steps"] = self._related_attacks({component_id: []})
            if change["before"] == change["after"]:
                decision = "no_review"
                rationale = "The before and after component states are identical."
            else:
                decision = "review_required"
                fields = ", ".join(evidence["changed_fields"])
                rationale = (
                    f"Known component {component_id} changed in: {fields}. "
                    "Existing attack paths and missing cross-component chains require review."
                )

        return {
            "change_id": change["change_id"],
            "change_type": change["type"],
            "component_id": component_id,
            "decision": decision,
            "rationale": rationale,
            "evidence": evidence,
        }

    @staticmethod
    def _changed_fields(before: Any, after: Any) -> list[str]:
        if isinstance(before, dict) and isinstance(after, dict):
            missing = object()
            return sorted(
                key
                for key in set(before) | set(after)
                if before.get(key, missing) != after.get(key, missing)
            )
        return [] if before == after else ["value"]

    @staticmethod
    def _base_evidence(change: JsonObject) -> JsonObject:
        source: JsonObject = {"name": change["source"]}
        if change.get("source_url"):
            source["url"] = change["source_url"]
        for field in ("published", "last_modified", "vulnerability_status"):
            if field in change:
                source[field] = change[field]
        evidence: JsonObject = {"source": source}
        if "cisa" in change:
            evidence["cisa"] = change["cisa"]
        return evidence

    def _related_scenarios(self, components: dict[str, list[str]]) -> list[str]:
        scenarios: set[str] = set()
        for component_id in components:
            scenarios.update(self._component_scenarios.get(component_id, set()))
            scenarios.update(
                reference.scenario_id
                for reference in self._component_attacks.get(component_id, [])
            )
        return sorted(scenarios)

    def _related_attacks(self, components: dict[str, list[str]]) -> list[JsonObject]:
        references: list[AttackReference] = []
        for component_id in components:
            references.extend(self._component_attacks.get(component_id, []))
        return [
            reference.as_dict()
            for reference in self._deduplicate_references(references)
        ]

    @staticmethod
    def _deduplicate_references(
        references: list[AttackReference],
    ) -> list[AttackReference]:
        unique = {(item.scenario_id, item.node_id): item for item in references}
        return [unique[key] for key in sorted(unique)]
