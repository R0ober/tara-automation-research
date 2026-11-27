# agents/stage1_agent.py
import json
import importlib
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from generation.tools.stageOneTools.stage_1_tools import stage1_tools
from generation.tools.stageOneTools.tool_dispatcher import get_item_definition, save_threat_scenario_to_db
from APIcaller import search_mitre_attack
from agents.iso_helper_agent import query_iso_expert

try:
    OpenAI = importlib.import_module("openai").OpenAI
except ModuleNotFoundError as exc:
    if exc.name != "openai":
        raise
    raise RuntimeError(
        "The 'openai' package is required. Install it with: python -m pip install openai"
    ) from exc

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY", "ollama"),
    base_url=os.getenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
)
def execute_tool(name, args):
    if name == "get_item_definition":
        return get_item_definition()
    elif name == "search_mitre_attack":
        print(f"Searching MITRE ATT&CK for keyword: {args.get('keyword', '')}")
        return search_mitre_attack(args.get("keyword", ""), limit=5)
    elif name == "save_threat_scenario_to_db":
        return save_threat_scenario_to_db(**args)
    elif name == "consult_iso_expert":
        return query_iso_expert(args.get("question", ""))
    else:
        return {"error": f"Unknown tool: {name}"}

def run_stage1_agent():
    system_prompt = """
You are the Stage 1 TARA Agent specializing in ISO/SAE 21434 Threat Analysis and Risk Assessment.
Your task is MANDATORY data generation across the target system:
1. First, call 'get_item_definition' to load the complete system architecture and item definition JSON.
2. Analyze all components, assets, and interfaces defined in the architecture. For this step, you also have access to the local MITRE ATT&CK database. You can call 'search_mitre_attack' for relevant threat techniques for each component or interface you analyze.
3. For each asset and threat identified, you MUST call the tool 'save_threat_scenario_to_db' to persist the structured relational data directly into 'tara_scenarios.db'. 

When calling 'save_threat_scenario_to_db', you must provide the following generalized arguments:
- component_id: Unique identifier of the component (e.g., COMP-VDCM)
- component_name: Name of the component
- trust_zone: Trust zone where the component resides
- asil_level: Safety integrity level (e.g., ASIL-D)
- interfaces: List of interface IDs belonging to this component
- asset_id: Unique identifier of the asset (e.g., ASSET-BRK-01)
- asset_name: Name or description of the asset being targeted
- cybersecurity_property: One of ['Confidentiality', 'Integrity', 'Availability']
- damage_scenario: Adverse vehicle-level consequence resulting from compromise
- safety_impact: Safety impact rating ['Severe', 'Major', 'Moderate', 'Negligible']
- operational_impact: Operational impact rating description
- threat_id: Unique threat scenario ID (e.g., TS-BRK-01)
- threat_description: Detailed description of the threat scenario
- root_cause: Underlying system flaw, missing control, or vulnerability root cause

4. Do NOT just output a text summary. You must systematically execute the 'save_threat_scenario_to_db' tool for every threat scenario you discover across all components.
5. Whenever you are unsure about impact rating criteria (safety, financial, operational, privacy), damage scenario definitions, or compliance requirements, you MUST use the `consult_iso_expert` tool to look up official rules from the standard before making a final rating.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Load the item definition, analyze the threats, and call 'save_threat_scenario_to_db' for each threat scenario to populate the database."}
    ]

    print("Stage 1 Agent: Threat Scenario & Impact Rating started...\n")
    
    turn_count = 0
    max_turns = 15 

    while turn_count < max_turns:
        turn_count += 1
    
    # Turn 1 Force reading the item definition first
        if turn_count == 1:
            current_tool_choice = {"type": "function", "function": {"name": "get_item_definition"}}
        # Turns 2..N-1 Force saving threat scenarios 
        elif turn_count < max_turns - 1:
            current_tool_choice = "required" # Forces ANY tool call 
        else:
            current_tool_choice = "auto"

        response = client.chat.completions.create(
            model="qwen3.5-65k",
            messages=messages,
            tools=stage1_tools,
            tool_choice=current_tool_choice,

        )
        
        msg = response.choices[0].message
        messages.append(msg)
        
        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                fn_name = tool_call.function.name
                try:
                    fn_args = json.loads(tool_call.function.arguments)
                except json.JSONDecodeError:
                    fn_args = {}

                print(f"[Tool Call]: {fn_name} with args keys: {list(fn_args.keys())}")
                
                result = execute_tool(fn_name, fn_args)
                print(f"[Tool Result]: {result}\n")
                
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })
        else:
            print("\n Stage 1 Agent Completed Execution!")
            print(msg.content)

if __name__ == "__main__":
    run_stage1_agent()