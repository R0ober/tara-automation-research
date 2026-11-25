import json
import sqlite3
import requests

DB_PATH = "./mitre_attack.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows dictionary-like access to rows
    return conn

# Callback 1: Standard SQL search over ICS + Enterprise MITRE ATT&CK
def search_mitre_attack(keyword: str, limit: int = 50):
    search_term = f"%{keyword.lower()}%"
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT attack_id, domain, name, tactics, platforms, description
        FROM techniques
        WHERE LOWER(attack_id) LIKE ? OR LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(platforms) LIKE ?
        LIMIT ?
    """
    
    cursor.execute(query, (search_term, search_term, search_term, search_term, limit))
    rows = cursor.fetchall()
    conn.close()
    
    # Convert sqlite3.Row objects to standard dictionaries
    return [dict(row) for row in rows]

# Callback 2: NIST NVD CVE Lookup with SQLite Caching
def check_component_cves(cpe_string: str, nvd_api_key: str = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check local cache first
    cursor.execute("SELECT response_json FROM cve_cache WHERE cpe = ?", (cpe_string,))
    cached = cursor.fetchone()
    if cached:
        conn.close()
        return json.loads(cached["response_json"])
    
    # Fetch from NIST NVD API if not cached
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_string}"
    headers = {"apiKey": nvd_api_key} if nvd_api_key else {}
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        conn.close()
        print(f"Error fetching CVEs from NVD API: {e}")
        return []

    cves = []
    vulnerabilities = data.get("vulnerabilities", [])
    for v in vulnerabilities:
        cve_data = v.get("cve", {})
        descriptions = cve_data.get("descriptions", [])
        desc_value = descriptions[0].get("value") if descriptions else None
        
        metrics = cve_data.get("metrics", {})
        cvss_v31 = metrics.get("cvssMetricV31", [{}])
        cvss_data = cvss_v31[0].get("cvssData", {}) if cvss_v31 else {}
        
        cves.append({
            "cve_id": cve_data.get("id"),
            "description": desc_value,
            "cvss_score": cvss_data.get("baseScore"),
            "attack_vector": cvss_data.get("attackVector")
        })

    # Save to local SQLite cache
    cursor.execute(
        "INSERT OR REPLACE INTO cve_cache (cpe, response_json, updated_at) VALUES (?, ?, ?)",
        (cpe_string, json.dumps(cves), int(__import__('time').time() * 1000))
    )
    conn.commit()
    conn.close()

    return cves