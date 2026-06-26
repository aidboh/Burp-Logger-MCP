# Burp Logger MCP

A standalone Burp Suite extension (Montoya API) that captures HTTP traffic from the Burp tools that
originate it (Proxy, Repeater, Intruder, Scanner, Target, Extensions), persists it to a
**per-project** SQLite database that survives restarts, and exposes it to an **MCP** client over a
localhost HTTP endpoint — so an AI agent can query, search, and triage your traffic and Scanner
findings the way Logger++ surfaces them in the UI.

## Features

- Captures traffic from the request-originating tools (Target, Proxy, Scanner, Intruder, Repeater,
  Extensions) via a single `HttpHandler`, with per-message **tool attribution**.
- **Per-project** persistent SQLite store — each Burp project gets its own isolated log; logs from
  one project never appear in another.
- **Per-tool logging toggles** plus an **All tools** master switch — log only what you care about.
- **Optional persistence** — keep logs on disk (default) or have this project's DB discarded when
  the extension unloads.
- **Substring and regex search** across url, headers, and bodies.
- **Batch body retrieval** so an agent can pull many full request/responses in one call.
- **Scanner findings** (audit issues) exposed live, with evidence.
- **Purge by tool, by age, or everything** (a full reset also compacts the file to reclaim disk),
  with a live storage readout in the UI.
- Async batched writer keeps logging off Burp's request path.

## MCP tools

| Tool | Purpose |
|------|---------|
| `list_logs` | Summary rows, newest first. Filter by tool/host/method/status, substring `search`, `regex`, and time range. Optional `include_bodies` returns full headers+bodies inline. |
| `get_log_entry` | Full headers + bodies for one id. |
| `get_log_entries` | Full entries for MANY ids in one call (up to 500) — avoids one call per id. |
| `get_stats` | Counts per tool, total entry count, earliest/latest timestamps. |
| `purge_logs` | Delete by tool and/or age (requires `confirm=true` to wipe everything). |
| `get_logging_config` / `set_logging_config` | View / change which tools are logged. |
| `list_findings` | Burp Scanner findings (audit issues), highest severity first; filter by severity/confidence/host. |
| `get_finding` | Full detail, remediation, background, and request/response evidence for one finding. |

Search notes: `search` is plain substring; `regex` is a Java regex (prefix `(?i)` for
case-insensitive). They combine with AND. Regex can't use an index, so narrow with other
filters first on large stores.

## Storage (per-project)

On load the extension reads a `projectId` from `api.persistence().extensionData()` (which lives
**inside the Burp project**); if absent it generates a UUID and saves it there. The SQLite file is
named after that id:

```
~/.burp-logger-mcp/projects/<uuid>.db
```

So each project has its own store, and reopening a project reconnects to its own DB.

> **Temporary projects:** Burp keeps `extensionData` in memory for temporary projects, so their
> UUID (and thus the link to the DB) is lost on close. For logs that survive restarts, use a
> **saved (disk) project**.

**Persistence toggle.** By default logs are kept on disk and survive restarts. Unchecking *Persist
logs to disk* in the tab deletes this project's DB files when the extension unloads (Burp close /
project switch); logging still works normally during the session. The preference is stored per
project. (This is delete-on-exit, not zero-disk — data is written during the session and removed on
a clean unload, so a hard crash could leave the file behind.)

**Reclaiming space.** Deleting rows alone doesn't shrink the SQLite file — SQLite reuses freed
pages rather than returning them to the OS. The full reset (*Purge ALL Logs / Reset Current Project
DB*, and the MCP `purge_logs` all-wipe) runs `VACUUM` afterward, so it compacts the file and the
storage readout drops. Per-tool and by-age purges don't shrink the file.

## Capture timing (important)

The capture hook is an `HttpHandler`, which only sees traffic that flows **after** the extension
is loaded. It cannot retrieve traffic that happened before. In particular, Burp's API exposes no
way to read past **Intruder** results, so an attack run before the extension was loaded is
unrecoverable — load the extension (with the relevant tool toggled on) **before** you run the work
you want logged. (Proxy is the only tool Burp could backfill via `api.proxy().history()`; that
import is not implemented here.)

## Build

Requires JDK 17+.

```bash
gradle shadowJar
# -> build/libs/burp-logger-mcp-0.1.2.jar
```

Set the Montoya version in `build.gradle.kts` to the latest you have. The dependencies
(`montoya-api` is compile-only; `sqlite-jdbc` and `gson` are bundled) resolve from Maven Central,
so the first build needs internet.

## Install

Burp → **Extensions → Installed → Add → Java →** select the shadow jar. The Output log prints the
DB path and the MCP endpoint (`http://127.0.0.1:8765/mcp`).

A **Logger MCP** tab appears with:

- the MCP endpoint and a live **Storage used** readout;
- a **Persist logs to disk** toggle (off = this project's DB is deleted when the extension unloads);
- an **All tools** master toggle, plus a per-tool toggle and **Purge** button for each tracked tool
  (Target, Proxy, Scanner, Intruder, Repeater, Extensions);
- **Purge ALL Logs / Reset Current Project DB** — clears this project's logs and compacts the file;
- **Delete ALL Project Databases** (bottom-right) — resets the current project and removes every
  other project's stored logs from disk.

## Connect an MCP client

The server speaks **Streamable-HTTP** on loopback. Use `127.0.0.1`, not `localhost` (the server
binds IPv4; `localhost` may resolve to IPv6 `::1` and fail to connect).

**Clients that support a remote/HTTP MCP server (e.g. Kiro IDE)** point straight at the URL. For
Kiro, add this to `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (user):

```json
{
  "mcpServers": {
    "burp-logs": {
      "url": "http://127.0.0.1:8765/mcp",
      "disabled": false,
      "autoApprove": ["list_logs", "get_log_entry", "get_log_entries", "get_stats", "get_logging_config", "list_findings", "get_finding"]
    }
  }
}
```

(If the client doesn't pick up the transport from `url` alone, add `"type": "http"` beside it.)

**Clients that only launch stdio servers** bridge via `mcp-remote`:

```json
{
  "mcpServers": {
    "burp-logs": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "http://127.0.0.1:8765/mcp"]
    }
  }
}
```

## Findings caveats

`list_findings` / `get_finding` read live from `api.siteMap().issues()`. Audit issues only exist in
Burp editions with **Scanner (Pro/DAST)** — on Community they return nothing.
