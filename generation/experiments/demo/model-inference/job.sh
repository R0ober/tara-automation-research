#!/bin/bash
#SBATCH --job-name=generation-inference
#SBATCH --gres=gpu:L4:1
#SBATCH --cpus-per-task=2
#SBATCH --mem=4G
#SBATCH --time=00:05:00
#SBATCH --output=slurm-%j.log

set -eu

# Runtime source: ghcr.io/ggml-org/llama.cpp@sha256:66444ea1e3ea17bff9338524b0e78004f2507de6e9cc39b2fb02897a1ccd9429
# Weights source: huggingface.co/bartowski/SmolLM2-135M-Instruct-GGUF at the revision below.
assets=${1:-"$HOME/tara-demo/model-inference/assets"}
revision=09816acd5d99df7be770d85ea30822623dab342c
model=SmolLM2-135M-Instruct-Q4_K_M.gguf
image="$assets/llama-cli-b12648-cuda.sif"
prompt="What is the capital of France? Answer in one word."

mkdir -p output
printf '%s\n' "model=bartowski/SmolLM2-135M-Instruct-GGUF" "revision=$revision" \
    "weights=$model" "runtime=llama.cpp-b12648-cuda" "prompt=$prompt" > output/run.txt
nvidia-smi --id="$SLURM_JOB_GPUS" --query-gpu=name,driver_version --format=csv >> output/run.txt

apptainer exec --nv --env LD_LIBRARY_PATH=/app:/.singularity.d/libs:/usr/local/cuda/lib64 \
    --bind "$assets:/models:ro" "$image" /app/llama-cli \
    --model "/models/$revision-$model" --device CUDA0 --gpu-layers 99 \
    --threads 2 --ctx-size 512 --n-predict 16 --temp 0 \
    --single-turn --simple-io --no-display-prompt --color off --prompt "$prompt" \
    > output/response.txt
