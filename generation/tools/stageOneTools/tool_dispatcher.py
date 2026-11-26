# tools/stage1_dispatcher.py
import sqlite3
import json
import os
from APIcaller import search_mitre_attack

TARADB_PATH = os.path.join(os.path.dirname(__file__), '../../databases/tara_scenarios.db')

def get_taradb_connection():
    conn = sqlite3.connect(TARADB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def get_item_definition():
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../'))

    json_path = os.path.join(project_root, 'shared', 'architecture', 'bbw', 'item-definition.json')
    
    if not os.path.exists(json_path):
        return {"error": f"Item definition JSON file not found at: {json_path}"}
        
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_threat_scenario_to_db(
    component_id: str,
    component_name: str,
    trust_zone: str,
    asil_level: str,
    interfaces: list,
    asset_id: str,
    asset_name: str,
    cybersecurity_property: str,
    damage_scenario: str,
    safety_impact: str,
    operational_impact: str,
    threat_id: str,
    threat_description: str,
    root_cause: str
):
    """
    Generically saves any component, asset, damage scenario, and threat scenario 
    into the normalized ISO 21434 database schema, initializing a root attack tree node for Agent 2.
    """
    conn = get_taradb_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Insert or Replace Component Profile
        cursor.execute("""
            INSERT OR REPLACE INTO components (component_id, name, trust_zone, asil_level, interfaces)
            VALUES (?, ?, ?, ?, ?)
        """, (component_id, component_name, trust_zone, asil_level, json.dumps(interfaces)))

        # 2. Insert or Replace Asset & Damage Scenario (Clause 15.3 & 15.5)
        cursor.execute("""
            INSERT OR REPLACE INTO assets (
                asset_id, component_id, name, cybersecurity_property, 
                damage_scenario, safety_impact, operational_impact
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            asset_id, component_id, asset_name, cybersecurity_property,
            damage_scenario, safety_impact, operational_impact
        ))

        # 3. Insert or Replace Threat Scenario (Clause 15.4)
        cursor.execute("""
            INSERT OR REPLACE INTO threat_scenarios (
                threat_id, asset_id, description, root_cause
            ) VALUES (?, ?, ?, ?)
        """, (
            threat_id, asset_id, threat_description, root_cause
        ))

        # 4. Initialize Root Attack Tree Node for Agent 2 (Clause 15.6)
        root_node_id = f"NODE-{threat_id}-ROOT"
        cursor.execute("""
            INSERT OR REPLACE INTO attack_tree_nodes (
                node_id, threat_id, parent_node_id, node_type, description, target_component_id, entry_point
            ) VALUES (?, ?, NULL, 'ROOT', ?, ?, ?)
        """, (
            root_node_id, threat_id, threat_description, component_id, "External Interface / Component Attack Surface"
        ))

        conn.commit()
        return {
            "status": "success", 
            "message": f"Threat scenario {threat_id} for asset {asset_id} successfully saved!"
        }
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()