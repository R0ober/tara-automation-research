#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 -m venv .venv
.venv/bin/python -m pip install --editable .

if [[ ! -f .env ]]; then
  cp .env.example .env
fi
if [[ ! -f config/maintenance.json ]]; then
  cp config/maintenance.example.json config/maintenance.json
fi
if [[ ! -f data/changes.json ]]; then
  mkdir -p data
  printf '{"changes": []}\n' > data/changes.json
fi
mkdir -p output

printf 'Local environment ready. Edit .env, config/maintenance.json, and data/changes.json.\n'
printf 'Run examples with: .venv/bin/tara-maintenance --config config/maintenance.example.json --changes examples/changes.json --stdout\n'
