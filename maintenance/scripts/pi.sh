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
exec npx --yes @earendil-works/pi-coding-agent@1.5.2 --approve "$@"
