#!/bin/bash
#SBATCH --job-name=generation-assets
#SBATCH --cpus-per-task=2
#SBATCH --mem=8G
#SBATCH --time=00:30:00
#SBATCH --output=slurm.log

set -eu
assets="$HOME/tara-demo/model-inference/assets"
mkdir -p "$assets"
cd "$assets"
exec 9>.prepare.lock
flock 9

# Publish each completed download with a rename on the same filesystem.
stage=$(mktemp -d .prepare-XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
fetch_weights() {
    local repo=$1 revision=$2 file=$3
    if [[ ! -s "$revision-$file" ]]; then
        curl --fail --location --silent --show-error --retry 2 \
            "https://huggingface.co/$repo/resolve/$revision/$file" -o "$stage/$file"
        mv "$stage/$file" "$revision-$file"
    fi
}

fetch_weights bartowski/SmolLM2-135M-Instruct-GGUF 09816acd5d99df7be770d85ea30822623dab342c SmolLM2-135M-Instruct-Q4_K_M.gguf
fetch_weights Qwen/Qwen2.5-1.5B-Instruct-GGUF 91cad51170dc346986eccefdc2dd33a9da36ead9 qwen2.5-1.5b-instruct-q4_k_m.gguf

runtime=llama-cli-b12648-cuda.sif
if [[ ! -s "$runtime" ]]; then
    apptainer pull --disable-cache "$stage/$runtime" \
        docker://ghcr.io/ggml-org/llama.cpp@sha256:66444ea1e3ea17bff9338524b0e78004f2507de6e9cc39b2fb02897a1ccd9429
    mv "$stage/$runtime" "$runtime"
fi
echo "Model weights and CUDA image ready in $assets"
