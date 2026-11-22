# agents/stage1_agent.py
import json
import importlib
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from tools.stage_1_tools import stage1_tools
from tools.tool_dispatcher import get_item_definition, save_threat_scenario_to_db
from APIcaller import search_mitre_attack

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

def execute_stage1_tool(name, args):
    if name == "get_item_definition":
        return get_item_definition()
    elif name == "search_mitre_attack":
        return search_mitre_attack(args.get("keyword", ""), limit=5)
    elif name == "save_threat_scenario_to_db":
        return save_threat_scenario_to_db(**args)
    else:
        raise ValueError(f"Unknown tool: {name}")

def run_stage1_agent():
    system_prompt = """
You are the Stage 1 TARA Agent specializing in ISO/SAE 21434 Threat Analysis and Risk Assessment.
Your tasks:
1. Call 'get_item_definition' to inspect the system components, data flows, and interfaces.
2. Identify critical assets and potential damage scenarios, applying rigorous ISO/SAE 21434 Annex F impact ratings (Safety, Financial, Operational, Privacy) such as Severe or Major.
3. Formulate corresponding threat scenarios with STRIDE classifications.
4. For each threat scenario identified, invoke 'save_threat_scenario_to_db' to write the structured record into 'tara_scenarios.db'.
Iterate systematically across the subsystem's critical assets until complete.
"""
    
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": "Please analyze the item definition, identify assets, damage scenarios, impact ratings, and threat scenarios, and save each one to the database using your tools."}
    ]

    print(" Stage 1 Agent: Threat Scenario & Impact Rating started...\n")
    
    keep_looping = True
    while keep_looping:
        response = client.chat.completions.create(
            model="gpt-4o", # Or local model tag if running on Ollama/vLLM
            messages=messages,
            tools=stage1_tools,
            tool_choice="auto"
        )
        
        msg = response.choices[0].message
        messages.append(msg)
        
        if msg.tool_calls:
            for tool_call in msg.tool_calls:
                fn_name = tool_call.function.name
                fn_args = json.loads(tool_call.function.arguments)
                print(f"🔧 [Stage 1 Tool Call]: {fn_name} -> ID: {fn_args.get('threat_scenario_id', fn_args.get('keyword', 'N/A'))}")
                
                result = execute_stage1_tool(fn_name, fn_args)
                
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": json.dumps(result)
                })
        else:
            keep_looping = False
            print("\n Stage 1 Agent Finished Successfully!")
            print(msg.content)

if __name__ == "__main__":
    run_stage1_agent()