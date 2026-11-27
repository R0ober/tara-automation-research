# tools/stage_2_dispatcher.py
import sqlite3
import json
import os

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

def get_root_threat_scenarios():
    conn = get_taradb_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            n.node_id as root_node_id,
            t.threat_id,
            t.description as threat_description,
            t.root_cause,
            a.asset_id,
            a.name as asset_name,
            a.cybersecurity_property,
            c.component_id,
            c.name as component_name,
            c.interfaces
        FROM attack_tree_nodes n
        JOIN threat_scenarios t ON n.threat_id = t.threat_id
        JOIN assets a ON t.asset_id = a.asset_id
        JOIN components c ON a.component_id = c.component_id
        WHERE n.parent_node_id IS NULL
    """)
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"root_threats": rows}

def add_attack_tree_node(**kwargs):
    clean_args = {k: v for k, v in kwargs.items() if k}
    
    node_id = clean_args.get("node_id")
    threat_id = clean_args.get("threat_id")
    parent_node_id = clean_args.get("parent_node_id")
    node_type = clean_args.get("node_type")
    description = clean_args.get("description")
    target_component_id = clean_args.get("target_component_id")
    entry_point = clean_args.get("entry_point")

    conn = get_taradb_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO attack_tree_nodes (
                node_id, threat_id, parent_node_id, node_type, description, target_component_id, entry_point
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (node_id, threat_id, parent_node_id, node_type, description, target_component_id, entry_point))
        conn.commit()
        return {"status": "success", "message": f"Attack tree node {node_id} added successfully."}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()

def save_attack_feasibility(**kwargs):
    clean_args = {k: v for k, v in kwargs.items() if k}
    
    feasibility_id = clean_args.get("feasibility_id")
    node_id = clean_args.get("node_id")
    attack_vector = clean_args.get("attack_vector")
    feasibility_rating = clean_args.get("feasibility_rating")
    elapsed_time = clean_args.get("elapsed_time", "N/A")
    specialist_expertise = clean_args.get("specialist_expertise", "N/A")
    knowledge_of_item = clean_args.get("knowledge_of_item", "N/A")
    window_of_opportunity = clean_args.get("window_of_opportunity", "N/A")
    equipment = clean_args.get("equipment", "N/A")

    conn = get_taradb_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO attack_feasibility (
                feasibility_id, node_id, attack_vector, elapsed_time, 
                specialist_expertise, knowledge_of_item, window_of_opportunity, 
                equipment, feasibility_rating
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            feasibility_id, node_id, attack_vector, elapsed_time,
            specialist_expertise, knowledge_of_item, window_of_opportunity,
            equipment, feasibility_rating
        ))
        conn.commit()
        return {"status": "success", "message": f"Feasibility rating {feasibility_rating} saved for node {node_id}."}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()