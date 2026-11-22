# seed_taradb.py
import sqlite3

DB_PATH = "./tara_scenarios.db"

schema = """
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    asset_name TEXT,
    parent_component TEXT,
    compromised_properties TEXT
);

CREATE TABLE IF NOT EXISTS damage_scenarios (
    damage_id TEXT PRIMARY KEY,
    description TEXT,
    safety_rating TEXT,
    safety_justification TEXT,
    financial_rating TEXT,
    financial_justification TEXT,
    operational_rating TEXT,
    operational_justification TEXT,
    privacy_rating TEXT,
    privacy_justification TEXT,
    overall_impact_rating TEXT
);

CREATE TABLE IF NOT EXISTS threat_scenarios (
    threat_scenario_id TEXT PRIMARY KEY,
    threat_scenario_name TEXT,
    asset_id TEXT,
    damage_id TEXT,
    stride_classification TEXT,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id),
    FOREIGN KEY (damage_id) REFERENCES damage_scenarios(damage_id)
);

CREATE TABLE IF NOT EXISTS attack_tree_nodes (
    node_id TEXT PRIMARY KEY,
    threat_scenario_id TEXT,
    parent_node_id TEXT,
    node_type TEXT, 
    gate TEXT, 
    title TEXT,
    description TEXT,
    target_component TEXT,
    target_interface TEXT,
    vulnerability_reference TEXT,
    technical_detail TEXT,
    attack_potential_score INTEGER,
    feasibility_rating TEXT,
    FOREIGN KEY (threat_scenario_id) REFERENCES threat_scenarios(threat_scenario_id)
);

CREATE TABLE IF NOT EXISTS risk_determinations (
    threat_scenario_id TEXT PRIMARY KEY,
    overall_impact_rating TEXT,
    aggregated_attack_feasibility TEXT,
    min_attack_potential_score INTEGER,
    inherent_risk_value INTEGER,
    inherent_risk_level TEXT,
    rationale TEXT,
    FOREIGN KEY (threat_scenario_id) REFERENCES threat_scenarios(threat_scenario_id)
);

CREATE TABLE IF NOT EXISTS risk_treatments (
    threat_scenario_id TEXT PRIMARY KEY,
    treatment_option TEXT,
    target_residual_feasibility TEXT,
    target_residual_risk_value INTEGER,
    target_residual_risk_level TEXT,
    FOREIGN KEY (threat_scenario_id) REFERENCES threat_scenarios(threat_scenario_id)
);

CREATE TABLE IF NOT EXISTS cybersecurity_requirements (
    requirement_id TEXT PRIMARY KEY,
    threat_scenario_id TEXT,
    target_component TEXT,
    description TEXT,
    FOREIGN KEY (threat_scenario_id) REFERENCES threat_scenarios(threat_scenario_id)
);
"""

def create_database():
    conn = sqlite3.connect(DB_PATH)
    # Enables foreign key constraints in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.executescript(schema)
    conn.commit()
    conn.close()
    print("Successfully created and initialized tara_scenarios.db!")

if __name__ == "__main__":
    create_database()