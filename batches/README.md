# `batches/` — job lists for the batch runners

Drop CSV / JSON files here that pair a CYBERSEC case ID with the scan
target.  Both runners accept files from anywhere on disk, but keeping
the curated lists in-repo gives a stable place to point CI at.

## Files in this directory

| File | Format | Consumed by |
|---|---|---|
| `example.csv` | `Case,Target` two-column CSV with `#`-prefixed comments | `scripts/batch-scan.sh --jobs-csv` / `scripts/windows/batch-scan.ps1 -JobsCsv` |
| `example.json` | Array of `{case, target}` objects | `scripts/batch-scan.sh --jobs-json` / `scripts/windows/batch-scan.ps1 -JobsJson` |

The runners auto-detect `-Format` from the target's extension (zip with
`.apk` inside → APK pipeline, `.zip` with `.exe`/`.msi` inside → Windows
installer pipeline, anything else → standard SCA pipeline), so the same
job list works for mixed-format batches.

## Recommended layout for daily / per-week batches

```
batches/
├── daily.csv             # every CYBERSEC ticket touched today
├── retention/
│   ├── 2026-W20.json     # one snapshot per week, archive-only
│   └── ...
└── README.md
```

`daily.csv` is what `make batch JOBS_CSV=batches/daily.csv` reads.

## Conventions

- Use absolute paths (the runners pass them verbatim to docker bind-mounts).
- One `Case` per line in CSV.  Lines whose `Case` column starts with `#`
  are skipped — convenient for temporarily disabling rows without losing
  the path.
- JSON keys are case-insensitive (`Case`/`case`, `Target`/`target`).
- Don't commit `daily.csv` if it leaks sensitive paths — keep it gitignored
  or use a separate dotfile.
