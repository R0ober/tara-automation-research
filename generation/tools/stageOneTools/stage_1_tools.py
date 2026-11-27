# tools/stage_1_tools.py

stage1_tools = [
    {
        "type": "function",
        "function": {
            "name": "get_item_definition",
            "description": "Read the item definition selected for this run, including its assets, components, and interfaces.",
            "parameters": {
                "type": "object",
                "properties": {}, 
                "required": []
            }
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
            "description": "Saves a systematically identified component, asset, damage scenario, and threat scenario into the normalized ISO 21434 database schema, initializing a root attack tree node for Agent 2.",
            "parameters": {
                "type": "object",
                "properties": {
                    "component_id": {"type": "string", "description": "Unique identifier of the component (e.g., COMP-VDCM)"},
                    "component_name": {"type": "string", "description": "Name of the component"},
                    "trust_zone": {"type": "string", "description": "Trust zone where the component resides"},
                    "asil_level": {"type": "string", "description": "Automotive Safety Integrity Level (e.g., ASIL-D)"},
                    "interfaces": {"type": "array", "items": {"type": "string"}, "description": "List of available interface IDs"},
                    "asset_id": {"type": "string", "description": "Unique identifier of the asset (e.g., ASSET-BRK-01)"},
                    "asset_name": {"type": "string", "description": "Name/description of the asset"},
                    "cybersecurity_property": {"type": "string", "enum": ["Confidentiality", "Integrity", "Availability"]},
                    "damage_scenario": {"type": "string", "description": "Adverse vehicle-level consequence"},
                    "safety_impact": {"type": "string", "enum": ["Severe", "Major", "Moderate", "Negligible"]},
                    "operational_impact": {"type": "string", "description": "Operational impact rating description"},
                    "threat_id": {"type": "string", "description": "Unique threat scenario ID (e.g., TS-BRK-01)"},
                    "threat_description": {"type": "string", "description": "Detailed description of the threat scenario"},
                    "root_cause": {"type": "string", "description": "Underlying system flaw or missing control causing the threat"}
                },
                "required": [
                    "component_id", "component_name", "trust_zone", "asil_level", "interfaces",
                    "asset_id", "asset_name", "cybersecurity_property", "damage_scenario",
                    "safety_impact", "operational_impact", "threat_id", "threat_description", "root_cause"
                ]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "consult_iso_expert",
            "description": "Consult the ISO/SAE 21434 expert agent for official compliance rules, impact criteria, or threat definitions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "The specific compliance or TARA methodology question."
                    }
                },
                "required": ["question"]
            }
        }
    }
]
