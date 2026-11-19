export const taraTools = [
  {
    type: "function",
    function: {
      name: "search_mitre_attack",
      description: "Searches local MITRE ATT&CK database (ICS and Enterprise) for attack techniques, tactics, or platforms.",
      parameters: {
        type: "object",
        properties: {
          keyword: {
            type: "string",
            description: "Search query (e.g., 'CAN bus', 'firmware modification', 'T0858', 'Linux')"
          }
        },
        required: ["keyword"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "check_component_cves",
      description: "Looks up known vulnerabilities and CVEs for a specific component CPE string.",
      parameters: {
        type: "object",
        properties: {
          cpe_string: {
            type: "string",
            description: "The CPE 2.3 string of the component (e.g., cpe:2.3:o:linux:linux_kernel:5.15.32:*:*:*:*:*:*:*)"
          }
        },
        required: ["cpe_string"]
      }
    }
  }
];