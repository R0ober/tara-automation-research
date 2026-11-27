#!/usr/bin/env python3
import argparse
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=10",
    "-o", "ServerAliveCountMax=2",
]
CONNECTION_HINT = (
    "Check your Chalmers network or VPN connection and SSH key. "
    "Test with: ssh -o BatchMode=yes -o ConnectTimeout=10 minerva hostname"
)


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
    print("Connecting to Minerva...", flush=True)
    try:
        result = subprocess.run(
            ["ssh", *SSH_OPTIONS, "minerva", create_dir],
            check=True, stdout=subprocess.PIPE, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired as error:
        raise ConnectionError(f"Minerva did not respond within 15 seconds. {CONNECTION_HINT}") from error
    except subprocess.CalledProcessError as error:
        if error.returncode == 255:
            raise ConnectionError(f"SSH could not connect to Minerva. {CONNECTION_HINT}") from error
        raise
    remote_dir = result.stdout.strip()
    destination = f"minerva:{remote_dir}"
    print(f"Remote run directory: {destination}", flush=True)

    if image_path is not None:
        subprocess.run(["scp", *SSH_OPTIONS, image_path, f"{destination}/image.sif"], check=True)
    if input_dir is not None:
        subprocess.run(["scp", *SSH_OPTIONS, "-r", input_dir.resolve(), f"{destination}/input"], check=True)
    subprocess.run(["scp", *SSH_OPTIONS, script_path, f"{destination}/job.sh"], check=True)
    return remote_dir


def main():
    parser = argparse.ArgumentParser(description="Upload a job to Minerva and submit it to Slurm.")
    parser.add_argument("--job-yaml", type=Path, required=True, help="Path to the job YAML file.")
    parser.add_argument("--input-dir", type=Path, help="Directory to upload as input/ in the run directory.")
    args = parser.parse_args()

    if not args.job_yaml.is_file():
        parser.error(f"Expected a job file at {args.job_yaml}")
    if args.input_dir is not None and not args.input_dir.is_dir():
        parser.error(f"Expected an input directory at {args.input_dir}")

    try:
        job = yaml.safe_load(args.job_yaml.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        parser.error(f"Could not read {args.job_yaml}: {error}")

    if not isinstance(job, dict):
        parser.error("Expected a YAML mapping for the job.")

    image_path = None
    if "image" in job:
        image = job["image"]
        if not isinstance(image, str) or not image.strip():
            parser.error("'image' must be a non-empty string.")
        image_path = (args.job_yaml.parent / image).resolve()
        if not image_path.is_file():
            parser.error(f"Expected an image file at {image_path}")

    if "script" in job:
        if "command" in job:
            parser.error("Choose either 'script' or 'command'.")
        script = job["script"]
        if not isinstance(script, str) or not script.strip():
            parser.error("'script' must be a non-empty path.")
        script_path = (args.job_yaml.parent / script).resolve()
        if not script_path.is_file():
            parser.error(f"Expected a job script at {script_path}")
    else:
        if image_path is None or args.input_dir is None:
            parser.error("A command job requires 'image' and --input-dir.")
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
    if args.input_dir is not None:
        print(f"Input directory: {args.input_dir}")
    print(f"Job script: {script_path}")

    try:
        remote_dir = upload_job(image_path, args.input_dir, script_path)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Upload failed: {error}\n")
    print("Upload complete.", flush=True)

    submit = shlex.join(["sbatch", "--chdir", remote_dir, f"{remote_dir}/job.sh"])
    try:
        subprocess.run(["ssh", *SSH_OPTIONS, "minerva", submit], check=True)
    except KeyboardInterrupt:
        parser.exit(130, "\nSubmission interrupted. Check your Minerva queue before retrying.\n")
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not confirm Slurm submission: {error}\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
