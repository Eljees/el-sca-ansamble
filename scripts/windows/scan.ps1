# Thin wrapper over the unified `cli scan` orchestrator (ADR-0005).
#
# Forwards all arguments to `python -m resilient_updates.cli scan`, the
# cross-platform entry point that supersedes run-scan.ps1 orchestration.
#
#   scripts\windows\scan.ps1 --target path\to\artifact.tar.gz --extract
#   scripts\windows\scan.ps1 --target path\to\artifact.tar.gz --dry-run
#
# NOTE: run-scan.ps1 remains the validated path until `cli scan` live mode has
# been exercised against the full docker-compose stack (ADR-0005 P3). Prefer
# --dry-run here to preview the plan; use run-scan.ps1 for production scans.
$ErrorActionPreference = "Stop"
python -m resilient_updates.cli scan @args
exit $LASTEXITCODE
