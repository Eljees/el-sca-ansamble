#!/usr/bin/env sh
set -eu

CONFIG_PATH="${CONFIG_PATH:-configs/feed_sources.yaml}"
python -m resilient_updates.cli --config "$CONFIG_PATH" update grype
