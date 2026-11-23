#!/usr/bin/env python3
import argparse
from pathlib import Path

import yaml


def main():
    parser = argparse.ArgumentParser(description="Validate a Minerva job file and its input directory.")
    parser.add_argument("--job-yaml", type=Path, required=True, help="Path to the job YAML file.")
    parser.add_argument("--input-dir", type=Path, required=True, help="Directory containing the job inputs.")
    args = parser.parse_args()

    if not args.job_yaml.is_file():
        parser.error(f"Expected a job file at {args.job_yaml}")
    if not args.input_dir.is_dir():
        parser.error(f"Expected an input directory at {args.input_dir}")

    try:
        job = yaml.safe_load(args.job_yaml.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        parser.error(f"Could not read {args.job_yaml}: {error}")

    if not isinstance(job, dict):
        parser.error("Expected a YAML mapping with 'image' and 'command' fields.")

    image = job.get("image")
    if not isinstance(image, str) or not image.strip():
        parser.error("'image' must be a non-empty string.")

    command = job.get("command")
    if not isinstance(command, list) or not command:
        parser.error("'command' must be a non-empty list of strings.")
    if not all(isinstance(argument, str) for argument in command):
        parser.error("Each entry in 'command' must be a string.")

    print(f"Job file: {args.job_yaml}")
    print(f"Input directory: {args.input_dir}")


if __name__ == "__main__":
    main()
