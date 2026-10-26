#!/usr/bin/env bash
# One-shot pipeline: download data -> prepare -> train both ensembles.
set -e
cd "$(dirname "$0")/.."

python setup_data.py
python phishguard/training/prepare_data.py
python phishguard/training/train_url.py
python phishguard/training/train_email.py

echo
echo "Training complete. Start the dashboard with:"
echo "  uvicorn phishguard.api.main:app --port 8000"
