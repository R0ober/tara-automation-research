import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Read the ID from an item definition.")
    parser.add_argument("input_path", type=Path, help="Item definition JSON file.")
    parser.add_argument("output_path", type=Path, help="File for the JSON result.")
    args = parser.parse_args()

    try:
        document = json.loads(args.input_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        parser.error(f"Could not read {args.input_path}: {error}")

    try:
        item_id = document["item_definition"]["item_id"]
    except (KeyError, TypeError):
        parser.error("Expected item_definition.item_id in the input file.")
    if not isinstance(item_id, str) or not item_id.strip():
        parser.error("Expected item_definition.item_id to be a non-empty string.")

    result = {"item_id": item_id}
    try:
        args.output_path.write_text(json.dumps(result) + "\n", encoding="utf-8")
    except OSError as error:
        parser.error(f"Could not write {args.output_path}: {error}")


if __name__ == "__main__":
    main()
