#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
python3 probability_simulation.py --participants 128 --runs 12800 --winners 1 --output output
