# tools/stage_1_tools.py

stage1_tools = [
    {
        "type": "function",
        "function": {
            "name": "get_item_definition",
            "description": "Load the system item definition and component architecture model JSON (e.g., braking system components and interfaces)."
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_mitre_attack",
            "description": "Search local MITRE ATT&CK database for relevant attack techniques or threat mechanisms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "Search term (e.g., 'spoofing', 'CAN', 'firmware')"
                    }
                },
                "required": ["keyword"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_threat_scenario_to_db",
            "description": "Save an identified asset, damage scenario with ISO/SAE 21434 Annex F impact ratings, and threat scenario with STRIDE classification to tara_scenarios.db.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "e.g., ASSET-BRK-01"},
                    "asset_name": {"type": "string"},
                    "parent_component": {"type": "string", "description": "e.g., COMP-BPSU"},
                    "compromised_properties": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List like ['Integrity', 'Authenticity', 'Availability']"
                    },
                    "damage_id": {"type": "string", "description": "e.g., DS-BRK-01"},
                    "damage_description": {"type": "string"},
                    "impact_ratings": {
                        "type": "object",
                        "properties": {
                            "Safety": {"type": "object", "properties": {"rating": {"type": "string"}, "justification": {"type": "string"}}},
                            "Financial": {"type": "object", "properties": {"rating": {"type": "string"}, "justification": {"type": "string"}}},
                            "Operational": {"type": "object", "properties": {"rating": {"type": "string"}, "justification": {"type": "string"}}},
                            "Privacy": {"type": "object", "properties": {"rating": {"type": "string"}, "justification": {"type": "string"}}},
                            "overall_impact_rating": {"type": "string"}
                        },
                        "required": ["Safety", "overall_impact_rating"]
                    },
                    "threat_scenario_id": {"type": "string", "description": "e.g., TS-BRK-01"},
                    "threat_scenario_name": {"type": "string"},
                    "stride_classification": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List like ['Spoofing', 'Tampering']"
                    }
                },
                "required": [
                    "asset_id", "asset_name", "parent_component", "compromised_properties",
                    "damage_id", "damage_description", "impact_ratings",
                    "threat_scenario_id", "threat_scenario_name", "stride_classification"
                ]
            }
        }
    }
]