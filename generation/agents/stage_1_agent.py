# agents/stage1_agent.py
import json
import importlib
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tools.stage_1_tools import stage1_tools
from tools.tool_dispatcher import get_item_definition, save_threat_scenario_to_db
from APIcaller import search_mitre_attack
from tools.tool_dispatcher import save_component_vulnerability

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
    elif name == "save_component_vulnerability":
        return save_component_vulnerability(**args) 
    else:
        return {"error": f"Unknown tool: {name}"}

def run_stage1_agent():
    system_prompt = """
You are the Stage 1 TARA Agent specializing in ISO/SAE 21434 Threat Analysis and Risk Assessment.
Your task is MANDATORY data generation:
1. First, call 'get_item_definition' to load the braking system architecture.
2. Analyze the components, assets, and interfaces. for this step, you allso have access to the local MITRE ATT&CK database. You MUST call 'search_mitre_attack' for relevant threats (e.g., firmware, CAN bus, spoofing) for each component or interface you analyze.
3. For each asset and threat identified, you MUST call the tool 'save_threat_scenario_to_db' to persist the asset, damage scenario, impact ratings, and threat scenario directly into 'tara_scenarios.db'. 
The following is information that needs to be inserted in to the database for every asset and threat/damage scenario that you find: 
    sset_id: str,
    asset_name: str,
    parent_component: str 
    compromised_properties: list 
    damage_id: str 
    damage_description: str 
    impact_ratings: dict
    threat_scenario_id: str
    threat_scenario_name: str 
    threat_scenario_description: str 
    stride_classification: list 
4. Do NOT just output a text summary. You must execute the 'save_threat_scenario_to_db' tool for every threat scenario you discover.
5. For each underlying vulnerability discovered on components or interfaces you MUST call 'save_component_vulnerability' so Stage 2 can build accurate attack trees from them.
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Load the item definition, analyze the threats, and call 'save_threat_scenario_to_db' for each threat scenario to populate the database."}
    ]

    print("🚀 Stage 1 Agent: Threat Scenario & Impact Rating started...\n")
    
    turn_count = 0
    max_turns = 10 # Prevent infinite loops

    while turn_count < max_turns:
        turn_count += 1
    
    # Turn 1: Force reading the item definition first
        if turn_count == 1:
            current_tool_choice = {"type": "function", "function": {"name": "get_item_definition"}}
        # Turns 2..N-1: Force saving threat scenarios (or let it search MITRE)
        elif turn_count < max_turns - 1:
            current_tool_choice = "required" # Forces ANY tool call (no chatting allowed)
        # Final turn: Allow it to finish with text
        else:
            current_tool_choice = "auto"

        response = client.chat.completions.create(
            model="qwen2.5",
            messages=messages,
            tools=stage1_tools,
            tool_choice=current_tool_choice
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
                
                # Execute the actual Python function (which writes to SQLite!)
                result = execute_tool(fn_name, fn_args)
                print(f"[Tool Result]: {result}\n")
                
                # Feed tool result back to the LLM
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })
        else:
            keep_looping = False
            print("\n Stage 1 Agent Completed Execution!")
            print(msg.content)

if __name__ == "__main__":
    run_stage1_agent()