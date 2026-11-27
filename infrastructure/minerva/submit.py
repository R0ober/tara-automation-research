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


def create_run_directory():
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
    return result.stdout.strip()


def upload_job(remote_dir, image_path, input_dir, script_path, verbose):
    destination = f"minerva:{remote_dir}"
    if image_path is not None:
        size_mib = image_path.stat().st_size / (1024 * 1024)
        print(f"Uploading {image_path.name} ({size_mib:.1f} MiB)...", flush=True)
        subprocess.run(["scp", *SSH_OPTIONS, image_path, f"{destination}/image.sif"], check=True)
    else:
        print("Uploading job files...", flush=True)
    # OpenSSH scp shows its progress meter when stdout is a terminal.
    # Leave stderr connected so transfer errors are always visible.
    output = None if verbose else subprocess.DEVNULL
    if input_dir is not None:
        subprocess.run(["scp", *SSH_OPTIONS, "-r", input_dir.resolve(), f"{destination}/input"],
                       check=True, stdout=output)
    subprocess.run(["scp", *SSH_OPTIONS, script_path, f"{destination}/job.sh"], check=True, stdout=output)


def submit_job(remote_dir):
    submit = shlex.join(["sbatch", "--parsable", "--chdir", remote_dir, f"{remote_dir}/job.sh"])
    result = subprocess.run(
        ["ssh", *SSH_OPTIONS, "minerva", submit], check=True, stdout=subprocess.PIPE, text=True,
    )
    job_id = result.stdout.strip().partition(";")[0]
    if not job_id.isdecimal():
        raise ValueError(f"Unexpected sbatch reply: {result.stdout.strip()!r}")
    return job_id


def main():
    parser = argparse.ArgumentParser(description="Upload a job to Minerva and submit it to Slurm.")
    parser.add_argument("--job-yaml", type=Path, required=True, help="Path to the job YAML file.")
    parser.add_argument("--input-dir", type=Path, help="Directory to upload as input/ in the run directory.")
    parser.add_argument("--verbose", action="store_true", help="Show local job paths and all file transfers.")
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

    if args.verbose:
        print(f"Job file: {args.job_yaml}")
        if args.input_dir is not None:
            print(f"Input directory: {args.input_dir}")
        print(f"Job script: {script_path}")
    try:
        remote_dir = create_run_directory()
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not create the run directory: {error}\n")

    run_files = f"Run files  minerva:{remote_dir}"
    try:
        upload_job(remote_dir, image_path, args.input_dir, script_path, args.verbose)
    except (OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Upload failed: {error}\n{run_files}\n")
    except KeyboardInterrupt:
        parser.exit(130, f"\nUpload interrupted. No job submitted.\n{run_files}\n")

    check_queue = "Check your Minerva queue before retrying."
    try:
        job_id = submit_job(remote_dir)
    except KeyboardInterrupt:
        parser.exit(130, f"\nSubmission interrupted. {check_queue}\n{run_files}\n")
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        parser.exit(1, f"Could not confirm Slurm submission: {error}\n{check_queue}\n{run_files}\n")
    print(f"\nSubmitted  Slurm job {job_id}\n{run_files}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)
