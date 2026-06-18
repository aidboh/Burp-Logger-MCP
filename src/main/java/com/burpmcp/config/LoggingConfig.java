package com.burpmcp.config;

import burp.api.montoya.core.ToolType;
import com.burpmcp.db.LogStore;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks which Burp tools are being logged. Defaults to enabled for the common tools.
 * Persisted as "TOOLNAME=true,TOOLNAME=false,..." under the config key below.
 */
public class LoggingConfig {

    private static final String KEY = "logging.tools";
    private final LogStore store;
    private final Map<String, Boolean> enabled = new ConcurrentHashMap<>();

    public LoggingConfig(LogStore store) {
        this.store = store;
        load();
    }

    private void load() {
        // Sensible defaults; the tools a pentester usually cares about.
        for (ToolType t : ToolType.values()) enabled.put(t.name(), defaultFor(t));
        String raw = store.getConfig(KEY);
        if (raw != null && !raw.isBlank()) {
            for (String pair : raw.split(",")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) enabled.put(kv[0].trim(), Boolean.parseBoolean(kv[1].trim()));
            }
        }
    }

    private static boolean defaultFor(ToolType t) {
        switch (t) {
            case PROXY:
            case REPEATER:
            case INTRUDER:
            case SCANNER:
                return true;
            default:
                return false; // SUITE, TARGET, etc. off by default to reduce noise
        }
    }

    public boolean isEnabled(ToolType t) {
        return enabled.getOrDefault(t.name(), false);
    }

    public void setEnabled(String toolName, boolean value) {
        enabled.put(toolName, value);
        persist();
    }

    public Map<String, Boolean> snapshot() {
        return new LinkedHashMap<>(enabled);
    }

    private void persist() {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Boolean> e : enabled.entrySet()) {
            if (sb.length() > 0) sb.append(',');
            sb.append(e.getKey()).append('=').append(e.getValue());
        }
        store.setConfig(KEY, sb.toString());
    }
}
