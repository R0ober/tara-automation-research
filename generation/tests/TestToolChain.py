import sys
import os

# Add the parent directory (generation/) to Python's module search path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from APIcaller import search_mitre_attack, check_component_cves
# If you have a ToolDispatcher in Python, you can import and test it similarly.

def run_tests():
    print("Starting Python Toolchain & Database Tests...\n")

    # Test 1: Search MITRE ATT&CK locally via SQLite
    print('Test 1: Searching MITRE ATT&CK for "firmware"...')
    mitre_results = search_mitre_attack('firmware', 10)
    print(f"Found {len(mitre_results)} techniques:")
    for t in mitre_results:
        print(f" - [{t['attack_id']}] ({t['domain']}) {t['name']}")
        print(f"   Tactics: {t['tactics']}")
        print(f"   Platforms: {t['platforms']}")
    print("\n--------------------------------------------------\n")


    # Test 2: Search with keyword 'CAN'
    print('Test 2: Searching MITRE ATT&CK for "CAN"...')
    can_results = search_mitre_attack('CAN', 5)
    print(f"Found {len(can_results)} results for 'CAN':")
    for t in can_results:
        print(f" - [{t['attack_id']}] ({t['domain']}) {t['name']}")
        print(f"   Tactics: {t['tactics']}")
        print(f"   Platforms: {t['platforms']}")
        print(f"   Description: {t['description'][:1000]}...")  # Print first 100 chars of description
    print("--------------------------------------------------\n")

    # Test 3: Test NVD CVE Lookup & Caching (using OpenSSL 3.0.4)
    print('Test 3: Checking CVEs for OpenSSL 3.0.4 (CPE)...')
    test_cpe = 'cpe:2.3:a:openssl:openssl:3.0.4:*:*:*:*:*:*:*'
    cve_results = check_component_cves(test_cpe)
    print(f"Found {len(cve_results)} vulnerabilities for OpenSSL 3.0.4:")
    for cve in cve_results:
        print(f" - {cve['cve_id']} (CVSS: {cve['cvss_score']}, Vector: {cve['attack_vector']})")

    print("\nAll Python tests completed successfully!")

if __name__ == "__main__":
    run_tests()