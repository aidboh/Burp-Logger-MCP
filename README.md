# Burp Logger MCP

A standalone Burp Suite extension (Montoya API) that captures HTTP traffic from **every**
Burp tool (Proxy, Repeater, Intruder, Scanner, Extensions, …), persists it to SQLite across
restarts, and exposes it to an **MCP** client over a localhost HTTP endpoint — so an LLM can
query, search, and manage your logs the way Logger++ surfaces them in the UI.

## Features

- Captures traffic from all tools via a single `HttpHandler`, with per-message **tool attribution**.
- **Persistent** SQLite store at `~/.burp-logger-mcp/logs.db` (survives reboots & project switches).
- **Per-tab logging toggles** — log only the tools you care about (via the *Logger MCP* tab or the `set_logging_config` MCP tool).
- **Purge by tab** or by age, or purge everything (via UI buttons or the `purge_logs` MCP tool).
- Async batched writer keeps logging off Burp's request path.

## MCP tools exposed

| Tool | Purpose |
|------|---------|
| `list_logs` | Summary rows, newest first; filter by tool/host/method/status/search/time. |
| `get_log_entry` | Full headers + bodies for one id. |
| `get_stats` | Counts per tool, totals, time range. |
| `purge_logs` | Delete by tool and/or age (requires `confirm=true` to wipe all). |
| `get_logging_config` / `set_logging_config` | View / change which tools are logged. |

## Build

Requires JDK 17+.

```bash
./gradlew shadowJar
# -> build/libs/burp-logger-mcp-0.1.0.jar
```

> Set the Montoya version in `build.gradle.kts` to the latest you have, and confirm method
> names against the current Montoya javadoc if your version differs.

## Install

Burp → **Extensions → Installed → Add → Java →** select the shadow jar.
A **Logger MCP** tab appears with per-tool checkboxes and purge buttons; the Output log prints
the DB path and the MCP endpoint (`http://127.0.0.1:8765/mcp`).

## Connect an MCP client

The server speaks **Streamable-HTTP** on loopback. For clients that only launch stdio servers,
bridge with `mcp-remote`:

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

Clients that support an HTTP/Streamable transport directly can point at that URL.

## Notes & next steps

- The `HttpHandler` registered on `api.http()` receives Proxy traffic too (tool = `PROXY`).
  If your Burp build omits anything you expect, also register
  `api.proxy().registerRequestHandler/registerResponseHandler` and de-dupe by `messageId`.
- Bodies are stored as text (`bodyToString`). For binary fidelity, add raw-bytes BLOB columns.
- Bind/port is hard-coded to `127.0.0.1:8765`; expose a setting if you need to change it.
- For large datasets, consider an SQLite FTS5 table to speed up `search`.
- The MCP layer is a minimal hand-rolled JSON-RPC implementation (no Jetty/Spring) to keep the
  extension a single jar. Swap in the official MCP Java SDK if you want richer transport features.
