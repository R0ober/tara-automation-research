#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

export PYTHON="${PYTHON:-$ROOT/.venv/bin/python}"

PROVIDER_ARGS=()
if [[ -n "${TARA_MAINTENANCE_PROVIDER:-}" ]]; then
  PROVIDER_ARGS=(--provider "$TARA_MAINTENANCE_PROVIDER")
fi

MODEL_ARGS=()
if [[ -n "${TARA_MAINTENANCE_MODEL:-}" ]]; then
  MODEL_ARGS=(--model "$TARA_MAINTENANCE_MODEL")
fi

exec npx --yes @earendil-works/pi-coding-agent@1.5.2 --approve "${PROVIDER_ARGS[@]}" "${MODEL_ARGS[@]}" "$@"
