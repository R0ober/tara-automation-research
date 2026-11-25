from stage_1_agent import run_tara_agent

system_prompt = """
You are an expert Automotive Cybersecurity Engineer specializing in TARA (Threat Analysis and Risk Assessment) 
according to ISO/SAE 21434. Your job is to analyze item definitions, look up relevant MITRE ATT&CK techniques, 
and identify component vulnerabilities using your tools.
"""

user_prompt = """
Please load the braking system item definition (AUTO-BBW-01), identify the core components, 
and search our local MITRE ATT&CK database for firmware or CAN bus related threats that could impact them.
"""

final_answer = run_tara_agent(system_prompt, user_prompt, model_name="gpt-4o")
print("\n--- Final Agent TARA Report ---")
print(final_answer)