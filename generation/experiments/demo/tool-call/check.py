"""Check one model-requested tool call against the item mounted at /input."""

import json
import subprocess
import sys
from pathlib import Path
from urllib.request import Request, urlopen


def chat(endpoint, messages, tools, tool_choice):
    payload = {
        "model": "item-model",
        "messages": messages,
        "tools": tools,
        "tool_choice": tool_choice,
        "temperature": 0,
        "max_tokens": 128,
    }
    request = Request(endpoint, data=json.dumps(payload).encode(),
                      headers={"Content-Type": "application/json"})
    with urlopen(request, timeout=60) as response:
        return json.load(response)["choices"][0]["message"]


def main():
    endpoint = sys.argv[1] + "/v1/chat/completions"
    tools = [{"type": "function", "function": {
        "name": "read_item_id",
        "description": "Read the item ID from the supplied item definition.",
        "parameters": {"type": "object", "properties": {}, "required": []},
    }}]
    messages = [
        {"role": "system", "content": "You have access to an item lookup tool. Call it to answer questions about the item. Once it returns, report its item_id."},
        {"role": "user", "content": "What is the item ID?"},
    ]
    trace = Path("/output/trace.json")
    try:
        reply = chat(endpoint, messages, tools, "required")
        messages.append(reply)
        calls = reply.get("tool_calls") or []
        if len(calls) != 1:
            raise ValueError("Expected one structured tool call")
        call = calls[0]
        function = call["function"]
        if function["name"] != "read_item_id" or json.loads(function["arguments"]) != {}:
            raise ValueError("Expected read_item_id with no arguments")

        result = Path("/output/result.json")
        subprocess.run([sys.executable, "/app/read_item.py", "/input/item-definition.json", result], check=True)
        messages.append({"role": "tool", "tool_call_id": call["id"], "content": result.read_text().strip()})
        final = chat(endpoint, messages, tools, "none")
        messages.append(final)
        item_id = json.loads(result.read_text())["item_id"]
        if final.get("tool_calls") or item_id not in (final.get("content") or ""):
            raise ValueError("Final answer did not report the tool result")
        print(f"Verified read_item_id: {item_id}")
    finally:
        trace.write_text(json.dumps({
            "tool_choice_by_turn": ["required", "none"],
            "messages": messages,
        }, indent=2) + "\n")


if __name__ == "__main__":
    main()
