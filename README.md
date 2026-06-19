# Burp Logger MCP

A standalone Burp Suite extension (Montoya API) that captures HTTP traffic from the Burp tools that
originate it (Proxy, Repeater, Intruder, Scanner, Target, Extensions), persists it to a
**per-project** SQLite database that survives restarts, and exposes it to an **MCP** client over a
localhost HTTP endpoint — so an AI agent can query, search, and triage your traffic and Scanner
findings the way Logger++ surfaces them in the UI.

## Features

- Captures traffic from all tools via a single `HttpHandler`, with per-message **tool attribution**.
- **Per-project** persistent SQLite store — each Burp project gets its own isolated log; logs from
  one project never appear in another.
- **Per-tab logging toggles** — log only the tools you care about.
- **Purge by tab** or by age, or purge everything.
- **Substring and regex search** across url, headers, and bodies.
- **Batch body retrieval** so an agent can pull many full request/responses in one call.
- **Scanner findings** (audit issues) exposed live, with evidence.
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
# -> build/libs/burp-logger-mcp-0.1.0.jar
```

Set the Montoya version in `build.gradle.kts` to the latest you have. The dependencies
(`montoya-api` is compile-only; `sqlite-jdbc` and `gson` are bundled) resolve from Maven Central,
so the first build needs internet.

## Install

Burp → **Extensions → Installed → Add → Java →** select the shadow jar. A **Logger MCP** tab
appears with per-tool checkboxes and purge buttons; the Output log prints the DB path and the MCP
endpoint (`http://127.0.0.1:8765/mcp`).

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
Burp editions with **Scanner (Pro/DAST)** — on Community they return nothing. On some older Montoya
builds, an issue's `requestResponses()` evidence can come back empty even when the GUI shows it;
if you see `evidence: []` for an issue that clearly has request/response tabs, that's the version
quirk, not a config problem.
