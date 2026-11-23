#!/usr/bin/env python3
import argparse
import shlex
import subprocess
import tempfile
from pathlib import Path

import yaml


def write_job_script(command):
    script = rf"""#!/bin/bash
#SBATCH --cpus-per-task=1
#SBATCH --time=00:05:00
#SBATCH --output=slurm.log

set -e
mkdir -p output
exec apptainer exec \
    --bind ./input:/input:ro \
    --bind ./output:/output \
    ./image.sif {shlex.join(command)}
"""
    run_dir = Path(tempfile.mkdtemp(prefix="minerva-run-"))
    script_path = run_dir / "job.sh"
    script_path.write_text(script, encoding="utf-8")
    return script_path


def upload_job(image_path, input_dir, script_path):
    create_dir = "mkdir -p ~/tara-demo && mktemp -d ~/tara-demo/run-$(date +%Y-%m-%d_%H-%M-%S)-XXXXXXXX"
    result = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "minerva", create_dir],
        check=True, stdout=subprocess.PIPE, text=True,
    )
    remote_dir = result.stdout.strip()
    destination = f"minerva:{remote_dir}"
    print(f"Remote run directory: {destination}", flush=True)

    subprocess.run(["scp", "-B", image_path, f"{destination}/image.sif"], check=True)
    subprocess.run(["scp", "-B", "-r", input_dir, f"{destination}/input"], check=True)
    subprocess.run(["scp", "-B", script_path, f"{destination}/job.sh"], check=True)
    return remote_dir


def main():
    parser = argparse.ArgumentParser(description="Upload a job to Minerva and submit it to Slurm.")
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
    image_path = (args.job_yaml.parent / image).resolve()
    if not image_path.is_file():
        parser.error(f"Expected an image file at {image_path}")

    command = job.get("command")
    if not isinstance(command, list) or not command:
        parser.error("'command' must be a non-empty list of strings.")
    if not all(isinstance(argument, str) for argument in command):
        parser.error("Each entry in 'command' must be a string.")

    try:
        script_path = write_job_script(command)
    except OSError as error:
        parser.error(f"Could not write the job script: {error}")

    print(f"Job file: {args.job_yaml}")
    print(f"Input directory: {args.input_dir}")
    print(f"Job script: {script_path}")

    try:
        remote_dir = upload_job(image_path, args.input_dir.resolve(), script_path)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Upload failed: {error}\n")
    print("Upload complete.", flush=True)

    submit = shlex.join(["sbatch", "--chdir", remote_dir, f"{remote_dir}/job.sh"])
    try:
        subprocess.run(["ssh", "-o", "BatchMode=yes", "minerva", submit], check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not confirm Slurm submission: {error}\n")


if __name__ == "__main__":
    main()
