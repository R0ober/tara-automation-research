import { searchMitreAttack, checkComponentCves } from '../APIcaller.js';
import { executeToolCall } from '../tools/ToolDispatcher.js';

async function runTests() {

  // Test 1: Search MITRE ATT&CK locally via SQLite
  console.log('Test 1: Searching MITRE ATT&CK for "firmware"...');
  const mitreResults = searchMitreAttack('firmware', 3);
  console.log(`Found ${mitreResults.length} techniques:`);
  mitreResults.forEach(t => {
    console.log(` - [${t.attack_id}] (${t.domain}) ${t.name}`);
  });
  console.log('\n--------------------------------------------------\n');

  // Test 2: Test Tool Dispatcher with MITRE search
  console.log('Test 2: Testing Tool Dispatcher with "search_mitre_attack"...');
  const dispatcherMitre = await executeToolCall('search_mitre_attack', { keyword: 'CAN' });
  console.log(`Dispatcher returned ${dispatcherMitre.length} results for "CAN".\n`);
  dispatcherMitre.forEach(t => {
    console.log(` - [${t.attack_id}] (${t.domain}) ${t.name}`);
  });
  console.log('--------------------------------------------------\n');

  // Test 3: Test NVD CVE Lookup & Caching (using OpenSSL 3.0.4 from your braking/OTA JSON)
  console.log('Test 3: Checking CVEs for OpenSSL 3.0.4 (CPE)...');
  const testCpe = 'cpe:2.3:a:openssl:openssl:3.0.4:*:*:*:*:*:*:*';
  const cveResults = await checkComponentCves(testCpe);
  console.log(`Found ${cveResults.length} vulnerabilities for OpenSSL 3.0.4:`);
  cveResults.forEach(cve => {
    console.log(` - ${cve.cve_id} (CVSS: ${cve.cvss_score}, Vector: ${cve.attack_vector})`);
  });

  console.log('\nAll tests completed successfully!');
}

runTests().catch(err => {
  console.error('Test failed:', err);
});