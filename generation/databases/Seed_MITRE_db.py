import json
import sqlite3
import re

DB_PATH = "./mitre_attack.db"

def clean_mitre_text(text: str) -> str:
    if not text:
        return ""
    # Remove (Citation: ...) tags
    text = re.sub(r'\(Citation:[^)]+\)', '', text)
    # Keep link text, strip URLs: [Text](URL) -> Text
    text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    return text.strip()

def seed_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.executescript("""
        DROP TABLE IF EXISTS techniques;
        DROP TABLE IF EXISTS cve_cache;

        CREATE TABLE techniques (
            attack_id TEXT PRIMARY KEY,
            domain TEXT,
            name TEXT,
            tactics TEXT,
            platforms TEXT,
            description TEXT,
            detection TEXT
        );

        CREATE INDEX idx_tech_search ON techniques(name, description);

        CREATE TABLE cve_cache (
            cpe TEXT PRIMARY KEY,
            response_json TEXT,
            updated_at INTEGER
        );
    """)

    files = [
        {"path": "../ics-attack.json", "domain": "ICS"},
        {"path": "../enterprise-attack.json", "domain": "Enterprise"}
    ]

    cursor.execute("BEGIN TRANSACTION")
    
    for file_info in files:
        print(f"Processing {file_info['path']}...")
        with open(file_info["path"], "r", encoding="utf-8") as f:
            raw_stix = json.load(f)
            
        for obj in raw_stix.get("objects", []):
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue

            external_refs = obj.get("external_references", [])
            attack_id = next((r.get("external_id") for r in external_refs if r.get("source_name") == "mitre-attack"), None)
            
            if not attack_id:
                continue

            name = obj.get("name", "")
            
            kill_chain = obj.get("kill_chain_phases", [])
            tactics = ", ".join([p.get("phase_name", "") for p in kill_chain])
            
            platforms = ", ".join(obj.get("x_mitre_platforms", []))
            
            description = clean_mitre_text(obj.get("description", ""))
            detection = clean_mitre_text(obj.get("x_mitre_detection", ""))

            cursor.execute("""
                INSERT OR REPLACE INTO techniques (attack_id, domain, name, tactics, platforms, description, detection)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (attack_id, file_info["domain"], name, tactics, platforms, description, detection))

    cursor.execute("COMMIT")
    conn.close()
    print("Successfully built mitre_attack.db in Python!")

if __name__ == "__main__":
    seed_database()