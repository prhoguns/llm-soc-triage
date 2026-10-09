#!/usr/bin/env bash
# Every model under every condition, then the summary. Resumable.
set -euo pipefail
cd "$(dirname "$0")/.."
MODELS=${MODELS:-"qwen2.5-coder:3b qwen2.5-coder:7b"}
for model in $MODELS; do
  for condition in baseline hardened injected injected+hardened injected+guard; do
    python -m triage.run --model "$model" --condition "$condition"
  done
done
python -m triage.report
