# seed_taradb.py
import sqlite3

DB_PATH = "./tara_scenarios.db"

schema = """
-- 1. Components and Attack Surfaces
CREATE TABLE components (
    component_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    trust_zone TEXT NOT NULL,
    asil_level TEXT,
    interfaces TEXT -- JSON list of interfaces (e.g., BLE, OBD-II, CAN)
);

-- 2. Assets and Damage Scenarios 
CREATE TABLE assets (
    asset_id TEXT PRIMARY KEY,
    component_id TEXT,
    name TEXT NOT NULL,
    cybersecurity_property TEXT CHECK(cybersecurity_property IN ('Confidentiality', 'Integrity', 'Availability')),
    damage_scenario TEXT NOT NULL,
    safety_impact TEXT CHECK(safety_impact IN ('Severe', 'Major', 'Moderate', 'Negligible')),
    operational_impact TEXT,
    FOREIGN KEY (component_id) REFERENCES components(component_id)
);

-- 3. Threat Scenarios 
CREATE TABLE threat_scenarios (
    threat_id TEXT PRIMARY KEY,
    asset_id TEXT,
    description TEXT NOT NULL,
    root_cause TEXT NOT NULL,
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

-- 4. Attack Tree Nodes & Paths 
CREATE TABLE attack_tree_nodes (
    node_id TEXT PRIMARY KEY,
    threat_id TEXT,
    parent_node_id TEXT, -- NULL for root threat scenario
    node_type TEXT CHECK(node_type IN ('ROOT', 'OR_GATE', 'AND_GATE', 'LEAF_EXPLOIT')),
    description TEXT NOT NULL,
    target_component_id TEXT,
    entry_point TEXT, -- e.g., 'Cellular Interface', 'OBD-II Port', 'Wheel-well Harness'
    FOREIGN KEY (threat_id) REFERENCES threat_scenarios(threat_id),
    FOREIGN KEY (parent_node_id) REFERENCES attack_tree_nodes(node_id),
    FOREIGN KEY (target_component_id) REFERENCES components(component_id)
);

-- 5. Attack Feasibility & Rating 
CREATE TABLE attack_feasibility (
    feasibility_id TEXT PRIMARY KEY,
    node_id TEXT,
    attack_vector TEXT CHECK(attack_vector IN ('Network', 'Adjacent', 'Local', 'Physical')),
    elapsed_time TEXT,
    specialist_expertise TEXT,
    knowledge_of_item TEXT,
    window_of_opportunity TEXT,
    equipment TEXT,
    feasibility_rating TEXT CHECK(feasibility_rating IN ('High', 'Medium', 'Low', 'Very low')),
    FOREIGN KEY (node_id) REFERENCES attack_tree_nodes(node_id)
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