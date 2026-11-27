"""Verify that the model can read the reviewed item with the Stage 1 tool."""

import argparse
import hashlib
import json
from pathlib import Path

from model_client import create_client, read_model_settings
from stage_1_tools import stage1_tools
from tool_dispatcher import get_item_definition


def write_result(path, result):
    path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


def fail_verification(path, result, reply, reason):
    result.update(verified=False, error=reason, raw_reply=reply.model_dump(exclude_none=True))
    write_result(path, result)
    raise SystemExit(f"{reason} See {path}.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--item", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    url, model = read_model_settings()
    result = {"model": model, "input_sha256": hashlib.sha256(args.item.read_bytes()).hexdigest()}
    client = create_client(url)
    tool = next(t for t in stage1_tools if t["function"]["name"] == "get_item_definition")
    messages = [
        {"role": "system", "content": "The reviewed item is already selected. Use get_item_definition with no arguments to read it."},
        {"role": "user", "content": "Load the reviewed item."},
    ]
    first_choice = client.chat.completions.create(
        model=model, messages=messages, tools=[tool],
        tool_choice={"type": "function", "function": {"name": "get_item_definition"}},
        temperature=0, max_tokens=128,
    ).choices[0]
    result["first_finish_reason"] = first_choice.finish_reason
    first = first_choice.message
    calls = first.tool_calls or []
    if len(calls) != 1 or calls[0].function.name != "get_item_definition":
        fail_verification(args.output, result, first, "Expected one get_item_definition call.")
    call = calls[0]
    result["tool_call"] = call.model_dump(exclude_none=True)
    try:
        arguments = json.loads(call.function.arguments)
    except json.JSONDecodeError as error:
        fail_verification(args.output, result, first, f"Invalid tool argument JSON: {error}")
    if arguments != {}:
        fail_verification(args.output, result, first, "get_item_definition takes no arguments.")

    document = get_item_definition(args.item)
    messages.extend([first, {
        "role": "tool", "tool_call_id": call.id, "content": json.dumps(document, separators=(",", ":")),
    }, {
        "role": "user", "content": "From the tool result, return a JSON object with item_id and component_id. Copy the item ID and any one component ID exactly as written.",
    }])
    final = client.chat.completions.create(
        model=model, messages=messages, response_format={"type": "json_object"}, temperature=0, max_tokens=128,
    ).choices[0].message
    try:
        answer = json.loads(final.content or "")
    except json.JSONDecodeError as error:
        fail_verification(args.output, result, final, f"Invalid answer JSON: {error}")
    result["answer"] = answer
    component_ids = [component["component_id"] for component in document["components"]]
    verified = (isinstance(answer, dict) and answer.get("item_id") == document["item_definition"]["item_id"]
                and answer.get("component_id") in component_ids)
    if not verified:
        fail_verification(args.output, result, final, "Model returned IDs that do not match the item.")
    result["verified"] = True
    write_result(args.output, result)
    print(f"Verified {answer['item_id']} and {answer['component_id']}.")


if __name__ == "__main__":
    main()
