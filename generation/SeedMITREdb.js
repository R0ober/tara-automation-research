// SeedMITREdb.js — Run with: node SeedMITREdb.js. only needed once to create the SQLite database from the MITRE ATT&CK JSON files. To run on updated MITRE ATT&CK JSON files, delete the existing mitre_attack.db and re-run this script.
import fs from 'fs';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync('./mitre_attack.db');

db.exec(`
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
`);

function cleanMitreText(text) {
  if (!text) return '';
  return text
    .replace(/\(Citation:[^)]+\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .replace(/\s+/g, ' ')
    .trim();
}

const insertTech = db.prepare(`
  INSERT OR REPLACE INTO techniques (attack_id, domain, name, tactics, platforms, description, detection)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

const files = [
  { path: './ics-attack.json', domain: 'ICS' },
  { path: './enterprise-attack.json', domain: 'Enterprise' }
];

db.exec('BEGIN TRANSACTION');
for (const file of files) {
  const rawStix = JSON.parse(fs.readFileSync(file.path, 'utf8'));
  for (const obj of rawStix.objects) {
    if (obj.type !== 'attack-pattern' || obj.revoked || obj.x_mitre_deprecated) continue;

    const attackId = obj.external_references?.find(r => r.source_name === 'mitre-attack')?.external_id;
    if (!attackId) continue;

    const name = obj.name || '';
    const tactics = (obj.kill_chain_phases?.map(p => p.phase_name) || []).join(', ');
    const platforms = (obj.x_mitre_platforms || []).join(', ');
    const description = cleanMitreText(obj.description);
    const detection = cleanMitreText(obj.x_mitre_detection);

    insertTech.run(attackId, file.domain, name, tactics, platforms, description, detection);
  }
}
db.exec('COMMIT');
console.log('Successfully built mitre_attack.db!');