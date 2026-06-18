package com.burpmcp.db;

/** One captured request/response pair (response fields may be null if the request never completed). */
public class LogEntry {
    public long id;            // assigned by SQLite on insert
    public String tool;        // ToolType name, e.g. "PROXY", "REPEATER"
    public long timestamp;     // epoch millis (request time)
    public String method;
    public String url;
    public String host;
    public int port;
    public String protocol;    // "http" / "https"
    public String path;
    public Integer statusCode; // null until response arrives
    public String requestHeaders;
    public String requestBody;
    public String responseHeaders;
    public String responseBody;
    public Integer requestLength;
    public Integer responseLength;
    public String mimeType;
}
