import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('./mitre_attack.db');

// Callback 1: Standard SQL search over ICS + Enterprise MITRE ATT&CK
export function searchMitreAttack(keyword, limit = 10) {
  const searchTerm = `%${keyword.toLowerCase()}%`;
  
  const stmt = db.prepare(`
    SELECT attack_id, domain, name, tactics, platforms, description
    FROM techniques
    WHERE LOWER(attack_id) LIKE ? OR LOWER(name) LIKE ? OR LOWER(description) LIKE ? OR LOWER(platforms) LIKE ?
    LIMIT ?
  `);

  return stmt.all(searchTerm, searchTerm, searchTerm, searchTerm, limit);
}

// Callback 2: NIST NVD CVE Lookup with SQLite Caching
export async function checkComponentCves(cpeString) {
  const cached = db.prepare('SELECT response_json FROM cve_cache WHERE cpe = ?').get(cpeString);
  if (cached) {
    return JSON.parse(cached.response_json);
  }

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpeString)}`;
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  const res = await fetch(url, { headers });
  const data = await res.json();

  const cves = data.vulnerabilities?.slice(0, 6).map(v => ({
    cve_id: v.cve.id,
    description: v.cve.descriptions?.[0]?.value,
    cvss_score: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore,
    attack_vector: v.cve.metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector
  })) || [];

  db.prepare('INSERT OR REPLACE INTO cve_cache (cpe, response_json, updated_at) VALUES (?, ?, ?)')
    .run(cpeString, JSON.stringify(cves), Date.now());

  return cves;
}