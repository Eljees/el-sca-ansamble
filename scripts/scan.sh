#!/usr/bin/env bash
# Thin wrapper over the unified `cli scan` orchestrator (ADR-0005).
#
# `cli scan` is the cross-platform entry point that supersedes the per-OS
# run-scan.sh / run-scan.ps1 orchestration: it builds the pipeline plan
# (preflight -> extract? -> syft -> per-tool db-status/scan -> collect-report
# -> summary -> diff -> manifest) and executes it via subprocess, with a single
# source of truth for the cve-bin-tool exit-code contract.
#
# This wrapper forwards all arguments unchanged so operators and CI can call a
# stable path:
#
#   scripts/scan.sh --target path/to/artifact.tar.gz --extract
#   scripts/scan.sh --target path/to/artifact.tar.gz --dry-run   # preview only
#
# NOTE: run-scan.sh remains the validated docker-compose path until `cli scan`
# live mode has been exercised against the full stack (ADR-0005 P3 — completed
# migration). Until then, prefer `--dry-run` here to preview, and run-scan.sh
# for production scans.
set -euo pipefail
exec python -m resilient_updates.cli scan "$@"
