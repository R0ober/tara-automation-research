# tools/stage1_dispatcher.py
import sqlite3
import json
import os
from APIcaller import search_mitre_attack

TARADB_PATH = os.path.join(os.path.dirname(__file__), '../tara_scenarios.db')

def get_taradb_connection():
    conn = sqlite3.connect(TARADB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def get_item_definition():
    # Automatically finds project root (tara-automation-research/) from anywhere
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    
    # Pointing to the exact filename from your screenshot: item-definition.json
    json_path = os.path.join(project_root, 'shared', 'architecture', 'bbw', 'item-definition.json')
    
    if not os.path.exists(json_path):
        return {"error": f"Item definition JSON file not found at: {json_path}"}
        
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_threat_scenario_to_db(
    asset_id: str = "ASSET-UNKNOWN",
    asset_name: str = "Unknown Asset",
    parent_component: str = "UNKNOWN",
    compromised_properties: list = None,
    damage_id: str = "DS-UNKNOWN",
    damage_description: str = "No description provided",
    impact_ratings: dict = None,
    threat_scenario_id: str = "TS-UNKNOWN",
    threat_scenario_name: str = "Unknown Threat",
    threat_scenario_description: str = "No description provided", 
    stride_classification: list = None
):
    compromised_properties = compromised_properties or ["Integrity"]
    impact_ratings = impact_ratings or {"Safety": {"rating": "Severe"}, "overall_impact_rating": "Severe"}
    stride_classification = stride_classification or ["Tampering"]

    conn = get_taradb_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Insert Asset
        cursor.execute("""
            INSERT OR REPLACE INTO assets (asset_id, asset_name, parent_component, compromised_properties)
            VALUES (?, ?, ?, ?)
        """, (asset_id, asset_name, parent_component, ",".join(compromised_properties)))

        # 2. Insert Damage Scenario & Impact Ratings
        safety = impact_ratings.get("Safety", {})
        financial = impact_ratings.get("Financial", {})
        operational = impact_ratings.get("Operational", {})
        privacy = impact_ratings.get("Privacy", {})
        
        cursor.execute("""
            INSERT OR REPLACE INTO damage_scenarios (
                damage_id, description, 
                safety_rating, safety_justification,
                financial_rating, financial_justification,
                operational_rating, operational_justification,
                privacy_rating, privacy_justification,
                overall_impact_rating
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            damage_id, damage_description,
            safety.get("rating"), safety.get("justification"),
            financial.get("rating"), financial.get("justification"),
            operational.get("rating"), operational.get("justification"),
            privacy.get("rating"), privacy.get("justification"),
            impact_ratings.get("overall_impact_rating", "Severe")
        ))

        # 3. Insert Threat Scenario (Including Description)
        cursor.execute("""
            INSERT OR REPLACE INTO threat_scenarios (
                threat_scenario_id, threat_scenario_name, description, asset_id, damage_id, stride_classification
            ) VALUES (?, ?, ?, ?, ?, ?)
        """, (
            threat_scenario_id, threat_scenario_name, threat_scenario_description, asset_id, damage_id, ",".join(stride_classification)
        ))

        conn.commit()
        return {"status": "success", "message": f"Threat scenario {threat_scenario_id} saved successfully with description!"}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()



def save_component_vulnerability(
    vuln_id: str = "VULN-UNKNOWN",
    threat_scenario_id: str = "TS-UNKNOWN",
    component_id: str = "COMP-UNKNOWN",
    interface_id: str = "INT-UNKNOWN",  
    vulnerability_name: str = "Unknown Vulnerability",
    vulnerability_reference: str = "N/A",
    technical_detail: str = "No detail provided"
):
    """Saves a discovered component vulnerability to tara_scenarios.db for Stage 2 attack tree generation."""
    conn = get_taradb_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT OR REPLACE INTO component_vulnerabilities (
                vuln_id, threat_scenario_id, component_id, interface_id, 
                vulnerability_name, vulnerability_reference, technical_detail
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            vuln_id, threat_scenario_id, component_id, interface_id, 
            vulnerability_name, vulnerability_reference, technical_detail
        ))
        conn.commit()
        return {"status": "success", "message": f"Vulnerability {vuln_id} linked to {threat_scenario_id} saved successfully!"}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()