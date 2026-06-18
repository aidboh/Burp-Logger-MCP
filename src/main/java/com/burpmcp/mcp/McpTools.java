package com.burpmcp.mcp;

import burp.api.montoya.core.ToolType;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogStore;
import com.burpmcp.scan.IssueProvider;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonElement;

import java.util.List;
import java.util.Map;

/**
 * Defines the MCP tools and executes calls. Tool results are returned as a JSON string
 * inside a single text content block, which is the friendliest shape for an LLM client.
 */
public class McpTools {

    private final LogStore store;
    private final LoggingConfig config;
    private final IssueProvider issues;
    private final Gson gson = new Gson();

    public McpTools(LogStore store, LoggingConfig config, IssueProvider issues) {
        this.store = store;
        this.config = config;
        this.issues = issues;
    }

    /** The tools/list payload. */
    public JsonArray listTools() {
        JsonArray arr = new JsonArray();

        arr.add(tool("list_logs",
                "List captured HTTP log entries (summary rows, newest first). Filter by tool/tab, host, " +
                "method, status, free-text search, regex, and time range. Use get_log_entry for full headers/bodies.",
                obj(
                    prop("tool", "string", "Burp tool/tab to filter by, e.g. PROXY, REPEATER, INTRUDER, SCANNER."),
                    prop("host", "string", "Substring match on host."),
                    prop("method", "string", "Exact HTTP method, e.g. GET, POST."),
                    propInt("status", "Exact HTTP status code."),
                    prop("search", "string", "Free-text substring across url/headers/bodies."),
                    prop("regex", "string", "Java regex matched against url/headers/bodies. Prefix with (?i) for " +
                            "case-insensitive. Combined with other filters via AND."),
                    propInt("since", "Only entries at/after this epoch-millis timestamp."),
                    propInt("until", "Only entries at/before this epoch-millis timestamp."),
                    propInt("limit", "Max rows (default 50, max 1000)."),
                    propInt("offset", "Rows to skip for pagination."),
                    propBool("include_bodies", "If true, return full headers+bodies inline for each matched row " +
                            "(one call, no get_log_entry follow-ups). Token-heavy: pair with a small limit."),
                    propInt("max_body_chars", "When include_bodies is true, truncate each body to this many chars " +
                            "(default 4000).")
                )));

        arr.add(tool("get_log_entry",
                "Fetch one full log entry by id, including request/response headers and bodies.",
                requireObj(new String[]{"id"},
                    propInt("id", "Entry id from list_logs."),
                    propInt("max_body_chars", "Truncate each body to this many chars (default 20000).")
                )));

        arr.add(tool("get_log_entries",
                "Fetch full entries (headers + bodies) for MANY ids in one call, so you don't have to call " +
                "get_log_entry per id. Survey with list_logs, then pass the ids you want here. Max 500 ids.",
                requireObj(new String[]{"ids"},
                    propArray("ids", "integer", "Entry ids from list_logs to fetch in full."),
                    propInt("max_body_chars", "Truncate each body to this many chars (default 20000).")
                )));

        arr.add(tool("get_stats",
                "Counts per tool, total entry count, and the earliest/latest timestamps.",
                obj()));

        arr.add(tool("purge_logs",
                "Delete log entries. Provide a tool to purge a specific tab, and/or before_timestamp to " +
                "purge older entries. To delete EVERYTHING (no tool, no timestamp) you must pass confirm=true.",
                obj(
                    prop("tool", "string", "Only purge entries from this tool/tab."),
                    propInt("before_timestamp", "Only purge entries older than this epoch-millis value."),
                    propBool("confirm", "Required true to purge all logs when no other filter is given.")
                )));

        arr.add(tool("get_logging_config",
                "Show which tools/tabs are currently being logged.",
                obj()));

        arr.add(tool("set_logging_config",
                "Enable or disable logging for a specific tool/tab going forward.",
                requireObj(new String[]{"tool", "enabled"},
                    prop("tool", "string", "Tool/tab name, e.g. PROXY, REPEATER, INTRUDER, SCANNER."),
                    propBool("enabled", "true to log this tool, false to stop.")
                )));

        arr.add(tool("list_findings",
                "List Burp Scanner findings (audit issues), highest severity first. Filter by severity, " +
                "confidence, or host. Use get_finding for full detail and request/response evidence. " +
                "Note: findings only exist in Burp editions with Scanner (Pro/DAST); empty otherwise.",
                obj(
                    prop("severity", "string", "Exact severity: HIGH, MEDIUM, LOW, or INFORMATION."),
                    prop("confidence", "string", "Exact confidence: CERTAIN, FIRM, or TENTATIVE."),
                    prop("host", "string", "Substring match on the finding's host."),
                    propInt("limit", "Max findings to return (default 50).")
                )));

        arr.add(tool("get_finding",
                "Fetch one finding by id, including detail, remediation, background, and the " +
                "request/response evidence that triggered it.",
                requireObj(new String[]{"id"},
                    prop("id", "string", "Finding id from list_findings."),
                    propInt("max_body_chars", "Truncate each evidence body to this many chars (default 20000).")
                )));

        return arr;
    }

    /** Execute a tool call; returns the text payload for the content block. `error[0]` set on failure. */
    public String call(String name, JsonObject args, boolean[] error) {
        try {
            switch (name) {
                case "list_logs": {
                    String regex = str(args, "regex");
                    if (regex != null) {
                        try { java.util.regex.Pattern.compile(regex); }
                        catch (java.util.regex.PatternSyntaxException pse) {
                            return fail(error, "invalid regex: " + pse.getMessage());
                        }
                    }
                    List<Map<String, Object>> rows = store.query(
                            str(args, "tool"), str(args, "host"), str(args, "method"),
                            intOrNull(args, "status"), str(args, "search"), regex,
                            longOrNull(args, "since"), longOrNull(args, "until"),
                            intOr(args, "limit", 50), intOr(args, "offset", 0));
                    boolean includeBodies = args.has("include_bodies") && args.get("include_bodies").getAsBoolean();
                    if (includeBodies && !rows.isEmpty()) {
                        List<Long> ids = new java.util.ArrayList<>();
                        for (Map<String, Object> r : rows) ids.add(((Number) r.get("id")).longValue());
                        Map<Long, Map<String, Object>> full = store.getByIds(ids, intOr(args, "max_body_chars", 4000));
                        List<Object> out = new java.util.ArrayList<>();
                        for (Map<String, Object> r : rows) {
                            Map<String, Object> f = full.get(((Number) r.get("id")).longValue());
                            out.add(f != null ? f : r); // fall back to summary if row vanished
                        }
                        return gson.toJson(Map.of("count", out.size(), "entries", out));
                    }
                    return gson.toJson(Map.of("count", rows.size(), "entries", rows));
                }
                case "get_log_entries": {
                    JsonElement idsEl = args.get("ids");
                    if (idsEl == null || !idsEl.isJsonArray() || idsEl.getAsJsonArray().size() == 0)
                        return fail(error, "ids (non-empty array of entry ids) is required");
                    List<Long> ids = new java.util.ArrayList<>();
                    for (JsonElement el : idsEl.getAsJsonArray()) {
                        try { ids.add(el.getAsLong()); } catch (Exception ignore) {}
                    }
                    if (ids.size() > 500) return fail(error, "too many ids; max 500 per call");
                    Map<Long, Map<String, Object>> found = store.getByIds(ids, intOr(args, "max_body_chars", 20000));
                    List<Object> ordered = new java.util.ArrayList<>();
                    for (Long id : ids) { Map<String, Object> e = found.get(id); if (e != null) ordered.add(e); }
                    return gson.toJson(Map.of("requested", ids.size(), "found", ordered.size(), "entries", ordered));
                }
                case "get_log_entry": {
                    Long id = longOrNull(args, "id");
                    if (id == null) return fail(error, "id is required");
                    Map<String, Object> e = store.getById(id, intOr(args, "max_body_chars", 20000));
                    if (e == null) return fail(error, "no entry with id " + id);
                    return gson.toJson(e);
                }
                case "get_stats":
                    return gson.toJson(store.stats());
                case "list_findings": {
                    List<Map<String, Object>> rows = issues.list(
                            str(args, "severity"), str(args, "confidence"), str(args, "host"),
                            intOr(args, "limit", 50));
                    return gson.toJson(Map.of("count", rows.size(), "findings", rows));
                }
                case "get_finding": {
                    String id = str(args, "id");
                    if (id == null) return fail(error, "id is required");
                    Map<String, Object> f = issues.get(id, intOr(args, "max_body_chars", 20000));
                    if (f == null) return fail(error, "no finding with id " + id);
                    return gson.toJson(f);
                }
                case "purge_logs": {
                    String tool = str(args, "tool");
                    Long before = longOrNull(args, "before_timestamp");
                    boolean confirm = args.has("confirm") && args.get("confirm").getAsBoolean();
                    if (tool == null && before == null && !confirm)
                        return fail(error, "Refusing to purge ALL logs without confirm=true.");
                    int n = store.purge(tool, before);
                    return gson.toJson(Map.of("deleted", n));
                }
                case "get_logging_config":
                    return gson.toJson(config.snapshot());
                case "set_logging_config": {
                    String tool = str(args, "tool");
                    if (tool == null || !args.has("enabled"))
                        return fail(error, "tool and enabled are required");
                    boolean valid = false;
                    for (ToolType t : ToolType.values()) if (t.name().equalsIgnoreCase(tool)) { tool = t.name(); valid = true; break; }
                    if (!valid) return fail(error, "unknown tool: " + tool);
                    config.setEnabled(tool, args.get("enabled").getAsBoolean());
                    return gson.toJson(config.snapshot());
                }
                default:
                    return fail(error, "unknown tool: " + name);
            }
        } catch (Exception ex) {
            return fail(error, "error: " + ex.getMessage());
        }
    }

    // ---- small helpers ----

    private static String fail(boolean[] error, String msg) { error[0] = true; return msg; }

    private static String str(JsonObject o, String k) {
        return o != null && o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsString() : null;
    }
    private static Integer intOrNull(JsonObject o, String k) {
        return o != null && o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsInt() : null;
    }
    private static int intOr(JsonObject o, String k, int d) {
        Integer v = intOrNull(o, k); return v == null ? d : v;
    }
    private static Long longOrNull(JsonObject o, String k) {
        return o != null && o.has(k) && !o.get(k).isJsonNull() ? o.get(k).getAsLong() : null;
    }

    private JsonObject tool(String name, String desc, JsonObject schema) {
        JsonObject t = new JsonObject();
        t.addProperty("name", name);
        t.addProperty("description", desc);
        t.add("inputSchema", schema);
        return t;
    }
    private JsonObject obj(JsonObject... props) {
        JsonObject schema = new JsonObject();
        schema.addProperty("type", "object");
        JsonObject p = new JsonObject();
        for (JsonObject pr : props) for (Map.Entry<String, JsonElement> e : pr.entrySet()) p.add(e.getKey(), e.getValue());
        schema.add("properties", p);
        return schema;
    }
    private JsonObject requireObj(String[] required, JsonObject... props) {
        JsonObject schema = obj(props);
        JsonArray req = new JsonArray();
        for (String r : required) req.add(r);
        schema.add("required", req);
        return schema;
    }
    private JsonObject prop(String name, String type, String desc) {
        JsonObject p = new JsonObject(); JsonObject f = new JsonObject();
        f.addProperty("type", type); f.addProperty("description", desc);
        p.add(name, f); return p;
    }
    private JsonObject propInt(String name, String desc)  { return prop(name, "integer", desc); }
    private JsonObject propBool(String name, String desc) { return prop(name, "boolean", desc); }
    private JsonObject propArray(String name, String itemType, String desc) {
        JsonObject p = new JsonObject(); JsonObject f = new JsonObject();
        f.addProperty("type", "array");
        JsonObject items = new JsonObject(); items.addProperty("type", itemType);
        f.add("items", items);
        f.addProperty("description", desc);
        p.add(name, f); return p;
    }
}
