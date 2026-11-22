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
    """Loads the braking system item definition JSON model."""
    json_path = os.path.join(os.path.dirname(__file__), '../../shared/reference-tara/Electronic_Brake-by-Wire_(BBW)_&_Regenerative_Braking_Subsystem.json')
    if not os.path.exists(json_path):
        return {"error": "Item definition JSON file not found."}
    with open(json_path, 'r', encoding='utf-8') as f:
        return json.load(f)

def save_threat_scenario_to_db(
    asset_id: str,
    asset_name: str,
    parent_component: str,
    compromised_properties: list,
    damage_id: str,
    damage_description: str,
    impact_ratings: dict,
    threat_scenario_id: str,
    threat_scenario_name: str,
    stride_classification: list
):
    """Writes mapped assets, damage scenarios, and threat scenarios to tara_scenarios.db."""
    conn = get_taradb_connection()
    cursor = conn.cursor()
    
    try:
        # 1. Insert Asset
        cursor.execute("""
            INSERT OR REPLACE INTO assets (asset_id, asset_name, parent_component, compromised_properties)
            VALUES (?, ?, ?, ?)
        """, (asset_id, asset_name, parent_component, ",".join(compromised_properties)))

        # 2. Insert Damage Scenario & Impact Ratings (ISO/SAE 21434 Annex F)
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

        # 3. Insert Threat Scenario
        cursor.execute("""
            INSERT OR REPLACE INTO threat_scenarios (
                threat_scenario_id, threat_scenario_name, asset_id, damage_id, stride_classification
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            threat_scenario_id, threat_scenario_name, asset_id, damage_id, ",".join(stride_classification)
        ))

        conn.commit()
        return {"status": "success", "message": f"Threat scenario {threat_scenario_id} saved successfully to tara_scenarios.db"}
    except Exception as e:
        conn.rollback()
        return {"status": "error", "message": str(e)}
    finally:
        conn.close()