# el-sca Docker-MCP bridge

A tiny **local** MCP server that lets an MCP client (Claude/Cowork) drive the
el-sca-ansamble scanner stack — validate the stack, update DBs, run scans, read
logs — through an **allow-listed** set of `docker compose` operations. No
arbitrary shell, no `shell=True`; service/tool/profile names are validated.

## Why

Cowork/Claude has no Docker access of its own and cannot type into your terminal.
This bridge runs **on your machine** (where Docker Desktop is reachable, e.g. WSL)
and exposes only the operations below over stdio, so the agent can launch
containers and scans from the repo.

## Prerequisites

- Docker Desktop running, `docker compose` works.
- Run it where Docker is reachable. In WSL your Python is **`python3`** (not `python`).

```bash
pip3 install "mcp>=1.2"
```

## Run / connect

The server speaks **stdio**. Register it with your MCP client. Example
`claude_desktop_config.json` (or the Cowork "add local MCP server" config):

```json
{
  "mcpServers": {
    "el-sca-docker": {
      "command": "python3",
      "args": ["/mnt/d/dev/el-sca-ansamble/tools/docker-mcp/server.py"],
      "env": { "EL_SCA_DIR": "/mnt/d/dev/el-sca-ansamble" }
    }
  }
}
```

If the client runs on Windows (not WSL), use the Windows path and `python`:

```json
{
  "mcpServers": {
    "el-sca-docker": {
      "command": "python",
      "args": ["D:\\dev\\el-sca-ansamble\\tools\\docker-mcp\\server.py"],
      "env": { "EL_SCA_DIR": "D:\\dev\\el-sca-ansamble" }
    }
  }
}
```

Quick sanity check before wiring it up:

```bash
EL_SCA_DIR=/mnt/d/dev/el-sca-ansamble python3 tools/docker-mcp/server.py    # should start and wait on stdio
python3 -m py_compile tools/docker-mcp/server.py                            # syntax check
```

## Tools

| Tool | Kind | What it does |
|---|---|---|
| `compose_config` | read-only | validate docker-compose schema |
| `list_services` | read-only | list compose services |
| `compose_ps` | read-only | running containers |
| `update_doctor` | read-only | reachability matrix (`cli update-doctor --json`) |
| `compose_logs(service, tail)` | read-only | recent logs for one service |
| `update_db(tool, proxy=None)` | action | run `<tool>-updater` (+ grype importer) |
| `run_scan(target, tool, extract, update_db, sbom_scan, proxy)` | action | full pipeline via `run-scan.sh` |
| `compose_down` | destructive | stop stack (volumes kept) |

## Proxy / "any point" (ADR-0007)

Pass `proxy="http://127.0.0.1:10808"` to `update_db`/`run_scan`. The bridge
**translates `127.0.0.1`/`localhost` → `host.docker.internal`** automatically so
the host's local proxy (e.g. xray on 10808) is reachable from inside containers,
and injects it as `HTTP(S)_PROXY` via compose's `x-proxy-env`.

## Security

- Only the tools above are reachable — there is no "run any command" tool.
- `cwd` is pinned to `EL_SCA_DIR`; the scan target is passed as argv/env (no shell
  interpolation).
- `compose_down` is the only destructive tool and removes **containers only**, never
  named volumes (your cached DBs survive).
- Treat this as remote-command-execution surface: only run it on a host you control,
  and don't expose its stdio to untrusted clients.
