package com.burpmcp.capture;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.HttpService;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogEntry;
import com.burpmcp.db.LogStore;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * A single HttpHandler registered on api.http() sees traffic from EVERY Burp tool
 * (Proxy, Repeater, Intruder, Scanner, Extensions, ...). Each message carries:
 *   - toolSource().toolType()  -> which tab/tool it came from
 *   - messageId()              -> stable id used to correlate request with its response
 *
 * Requests are stashed in `pending` keyed by messageId; when the response arrives we
 * combine and enqueue a complete LogEntry. A sweeper flushes requests that never got a
 * response (timeouts/dropped) as response-less entries so nothing is silently lost.
 */
public class HttpCaptureHandler implements HttpHandler, AutoCloseable {

    private static final long PENDING_TTL_MS = 60_000;

    private final LogStore store;
    private final LoggingConfig config;
    private final Map<Integer, LogEntry> pending = new ConcurrentHashMap<>();
    private final ScheduledExecutorService sweeper =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "burpmcp-sweeper");
                t.setDaemon(true);
                return t;
            });

    public HttpCaptureHandler(LogStore store, LoggingConfig config) {
        this.store = store;
        this.config = config;
        sweeper.scheduleWithFixedDelay(this::sweep, PENDING_TTL_MS, PENDING_TTL_MS, TimeUnit.MILLISECONDS);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent req) {
        try {
            ToolType tool = req.toolSource().toolType();
            if (config.isEnabled(tool)) {
                LogEntry e = new LogEntry();
                e.tool = tool.name();
                e.timestamp = System.currentTimeMillis();
                e.method = req.method();
                e.url = safeUrl(req);
                HttpService svc = req.httpService();
                if (svc != null) {
                    e.host = svc.host();
                    e.port = svc.port();
                    e.protocol = svc.secure() ? "https" : "http";
                }
                e.path = req.path();
                e.requestHeaders = headersToString(req.headers());
                e.requestBody = req.bodyToString();
                e.requestLength = req.toByteArray().length();
                pending.put(req.messageId(), e);
            }
        } catch (Exception ignored) {
            // never break Burp's traffic flow because of logging
        }
        return RequestToBeSentAction.continueWith(req);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived resp) {
        try {
            LogEntry e = pending.remove(resp.messageId());
            if (e != null) {
                e.statusCode = (int) resp.statusCode();
                e.responseHeaders = headersToString(resp.headers());
                e.responseBody = resp.bodyToString();
                e.responseLength = resp.toByteArray().length();
                try { e.mimeType = resp.mimeType().toString(); } catch (Exception ignore) {}
                store.enqueue(e);
            }
        } catch (Exception ignored) {
        }
        return ResponseReceivedAction.continueWith(resp);
    }

    /** Flush requests that aged out without a response. */
    private void sweep() {
        long cutoff = System.currentTimeMillis() - PENDING_TTL_MS;
        for (Map.Entry<Integer, LogEntry> en : pending.entrySet()) {
            if (en.getValue().timestamp < cutoff && pending.remove(en.getKey()) != null) {
                store.enqueue(en.getValue()); // response fields stay null
            }
        }
    }

    private static String safeUrl(HttpRequestToBeSent req) {
        try { return req.url(); } catch (Exception e) { return null; }
    }

    private static String headersToString(List<HttpHeader> headers) {
        if (headers == null) return null;
        StringBuilder sb = new StringBuilder();
        for (HttpHeader h : headers) sb.append(h.name()).append(": ").append(h.value()).append('\n');
        return sb.toString();
    }

    @Override
    public void close() {
        sweeper.shutdownNow();
        // flush whatever is still pending
        for (Map.Entry<Integer, LogEntry> en : pending.entrySet()) store.enqueue(en.getValue());
        pending.clear();
    }
}
