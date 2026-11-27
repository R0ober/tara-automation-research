# tools/stage_2_tools.py

stage2_tools = [
    {
        "type": "function",
        "function": {
            "name": "get_root_threat_scenarios",
            "description": "Retrieves all root threat scenarios and component interfaces saved by Stage 1 from the database.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_item_definition",
            "description": "Loads the complete system architecture and item definition JSON. Use this to verify component interfaces, trust zones, and security configurations before building attack tree nodes.",
            "parameters": {"type": "object", "properties": {}}
        }
    },
    {
        "type": "function",
        "function": {
            "name": "add_attack_tree_node",
            "description": "Adds a node (AND_GATE, OR_GATE, or LEAF_EXPLOIT) to the attack tree hierarchy for a given threat scenario (ISO Clause 15.6).",
            "parameters": {
                "type": "object",
                "properties": {
                    "node_id": {"type": "string", "description": "Unique identifier for this node (e.g., NODE-TS-01-STEP1)"},
                    "threat_id": {"type": "string", "description": "The parent threat ID this node belongs to (e.g., TS-BRK-01)"},
                    "parent_node_id": {"type": "string", "description": "The parent node ID this connects to in the tree"},
                    "node_type": {"type": "string", "enum": ["OR_GATE", "AND_GATE", "LEAF_EXPLOIT"], "description": "Type of tree node logic or exploit step"},
                    "description": {"type": "string", "description": "Description of the attack step or gate condition"},
                    "target_component_id": {"type": "string", "description": "Target component ID being exploited at this step"},
                    "entry_point": {"type": "string", "description": "Interface or access vector used (e.g., Cellular Interface, OBD-II Port)"}
                },
                "required": ["node_id", "threat_id", "parent_node_id", "node_type", "description", "target_component_id", "entry_point"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "save_attack_feasibility",
            "description": "Assigns attack feasibility ratings and potential parameters to an attack path node in accordance with ISO 21434 Clause 15.7 and Annex G.",
            "parameters": {
                "type": "object",
                "properties": {
                    "feasibility_id": {"type": "string", "description": "Unique ID for this feasibility record (e.g., FEAS-NODE-01)"},
                    "node_id": {"type": "string", "description": "The attack tree node ID being rated"},
                    "attack_vector": {"type": "string", "enum": ["Network", "Adjacent", "Local", "Physical"], "description": "Predominant attack vector"},
                    "feasibility_rating": {"type": "string", "enum": ["High", "Medium", "Low", "Very low"], "description": "ISO 21434 attack feasibility rating"},
                    "elapsed_time": {"type": "string", "description": "Estimated elapsed time for exploit (e.g., <=1 week)"},
                    "specialist_expertise": {"type": "string", "description": "Required expertise (e.g., Proficient, Expert)"},
                    "knowledge_of_item": {"type": "string", "description": "Required knowledge (e.g., Public, Restricted)"},
                    "window_of_opportunity": {"type": "string", "description": "Access availability (e.g., Unlimited, Easy)"},
                    "equipment": {"type": "string", "description": "Required equipment (e.g., Standard, Specialized)"}
                },
                "required": ["feasibility_id", "node_id", "attack_vector", "feasibility_rating"]
            }
        }
    }
]