#!/bin/bash
#SBATCH --job-name=generation-tool-call
#SBATCH --gres=gpu:L4:1
#SBATCH --cpus-per-task=2
#SBATCH --mem=6G
#SBATCH --time=00:05:00
#SBATCH --output=slurm-%j.log

set -eu

assets="$HOME/tara-demo/model-inference/assets"
if [[ ! -f input/item-definition.json ]]; then
    echo "Pass --input-dir with a directory containing item-definition.json." >&2
    exit 1
fi
revision=91cad51170dc346986eccefdc2dd33a9da36ead9
weights="$revision-qwen2.5-1.5b-instruct-q4_k_m.gguf"
mkdir -p output
port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
endpoint="http://127.0.0.1:$port"

apptainer exec --nv --env LD_LIBRARY_PATH=/app:/.singularity.d/libs:/usr/local/cuda/lib64 \
    --bind "$assets:/models:ro" "$assets/llama-cli-b12648-cuda.sif" /app/llama serve \
    --model "/models/$weights" --alias item-model --device CUDA0 --gpu-layers 99 \
    --threads 2 --ctx-size 2048 --jinja --host 127.0.0.1 --port "$port" > output/server.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true; wait "$server_pid" || true' EXIT

until curl --silent --fail --max-time 2 "$endpoint/health" > /dev/null; do
    if ! kill -0 "$server_pid" 2>/dev/null || (( SECONDS >= 90 )); then
        echo "Model server did not become ready. See output/server.log." >&2
        exit 1
    fi
    sleep 1
done

apptainer exec --bind ./input:/input:ro --bind ./output:/output \
    ./image.sif python3 /app/check.py "$endpoint"
