import { searchMitreAttack } from '../APIcaller.js';
import { checkComponentCves } from '../APIcaller.js';

export async function executeToolCall(toolName, args) {
  switch (toolName) {
    case "search_mitre_attack":
      return searchMitreAttack(args.keyword);
      
    case "check_component_cves":
      return await checkComponentCves(args.cpe_string);
      
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}