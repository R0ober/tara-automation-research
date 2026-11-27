
import os
import sys

# Add parent directory to path so it can find APIcaller from the root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from APIcaller import search_local_iso_database


def query_iso_expert(question: str, *, client, model: str) -> str:
    """
    Simulates an ISO expert agent that searches the standard 
    and answers compliance questions for the TARA pipeline.
    """
  
    relevant_iso_text = search_local_iso_database(question) 

    system_prompt = f"""
    You are an expert automotive cybersecurity engineer certified in ISO/SAE 21434:2021.
    Your job is to provide precise compliance rules, damage scenario definitions, 
    and impact rating criteria based strictly on the standard snippets provided below.
    
    Reference Material from ISO/SAE 21434:
    {relevant_iso_text}
    """
    print(f"Consulting ISO Expert Agent with question: '{question}'\n")

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question}
        ],
        temperature=0.1, 
        
    )
    return response.choices[0].message.content

