import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile


GENERATION = Path(__file__).resolve().parent
TARAV = GENERATION / "tarav/bin/tarav"
SUBMIT = GENERATION.parent / "infrastructure/minerva/submit.py"


def main():
    parser = argparse.ArgumentParser(description="Review an item definition before submitting a Minerva job.")
    parser.add_argument("--item", required=True, type=Path, help="Item definition to review.")
    parser.add_argument("--job-yaml", required=True, type=Path, help="Job to submit after approval.")
    args = parser.parse_args()

    if not args.item.is_file():
        parser.error(f"Expected an item definition at {args.item}")
    if not args.job_yaml.is_file():
        parser.error(f"Expected a job file at {args.job_yaml}")
    if not TARAV.is_file():
        parser.error("Build tarav first: (cd generation/tarav && go build -o bin/tarav ./cmd/tarav)")

    review = subprocess.run(
        [TARAV, "serve", "--review", "--open", "--addr", "127.0.0.1:0", args.item.resolve()],
        stdout=subprocess.PIPE,
    )
    if review.returncode != 0:
        return review.returncode

    record = json.loads(review.stdout)
    item_bytes = args.item.read_bytes()
    if not isinstance(record, dict) or record.get("approved") is not True:
        parser.exit(1, "Missing approval record. Submission stopped.\n")
    if hashlib.sha256(item_bytes).hexdigest() != record.get("sha256"):
        parser.exit(1, "The item changed after approval. Review it again.\n")

    with tempfile.TemporaryDirectory(prefix="tara-reviewed-") as folder:
        (Path(folder) / "item-definition.json").write_bytes(item_bytes)
        job = subprocess.run([sys.executable, SUBMIT, "--job-yaml", args.job_yaml, "--input-dir", folder])
        return job.returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.exit(f"Review or submission failed: {error}")
    except KeyboardInterrupt:
        sys.exit(130)
