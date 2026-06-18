package com.burpmcp.mcp;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Minimal Model Context Protocol server speaking JSON-RPC 2.0 over HTTP, bound to loopback.
 *
 * Implemented on raw java.net.ServerSocket (java.base) rather than com.sun.net.httpserver,
 * because Burp ships a trimmed jlink runtime that omits the jdk.httpserver module.
 *
 * This is the request/response half of the Streamable-HTTP transport: the client POSTs a
 * JSON-RPC message and gets a JSON response. No server-initiated SSE (tool calls only), so
 * GET returns 405, which the transport spec permits.
 *
 * Supported methods: initialize, notifications/initialized, ping, tools/list, tools/call.
 * stdio-only clients can bridge with:  npx -y mcp-remote http://127.0.0.1:<port>/mcp
 */
public class McpHttpServer {

    private static final String PROTOCOL_VERSION = "2025-06-18";

    private final int port;
    private final McpTools tools;
    private final Consumer<String> log;
    private final Gson gson = new Gson();
    private final String sessionId = UUID.randomUUID().toString();

    private ServerSocket serverSocket;
    private ExecutorService pool;
    private Thread acceptThread;
    private volatile boolean running = false;

    public McpHttpServer(int port, McpTools tools, Consumer<String> log) {
        this.port = port;
        this.tools = tools;
        this.log = log;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket();
        serverSocket.setReuseAddress(true);
        serverSocket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        pool = Executors.newFixedThreadPool(8, r -> {
            Thread t = new Thread(r, "burpmcp-http");
            t.setDaemon(true);
            return t;
        });
        running = true;
        acceptThread = new Thread(this::acceptLoop, "burpmcp-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        log.accept("[burpmcp] MCP server listening on http://127.0.0.1:" + port + "/mcp");
    }

    public void stop() {
        running = false;
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (pool != null) pool.shutdownNow();
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket s = serverSocket.accept();
                pool.submit(() -> handle(s));
            } catch (IOException e) {
                if (running) log.accept("[burpmcp] accept error: " + e);
            }
        }
    }

    private void handle(Socket socket) {
        try (socket) {
            socket.setSoTimeout(30_000);
            InputStream in = socket.getInputStream();

            String requestLine = readLine(in);
            if (requestLine == null || requestLine.isEmpty()) return;
            String method = requestLine.split(" ", 2)[0];

            int contentLength = 0;
            String line;
            while ((line = readLine(in)) != null && !line.isEmpty()) {
                int idx = line.indexOf(':');
                if (idx > 0 && line.substring(0, idx).trim().equalsIgnoreCase("Content-Length")) {
                    try { contentLength = Integer.parseInt(line.substring(idx + 1).trim()); }
                    catch (NumberFormatException ignored) {}
                }
            }

            OutputStream out = socket.getOutputStream();

            if (method.equalsIgnoreCase("OPTIONS")) { writeResponse(out, 204, null); return; }
            if (!method.equalsIgnoreCase("POST"))   { writeResponse(out, 405, null); return; }

            byte[] body = readBytes(in, contentLength);
            String json = handleBody(new String(body, StandardCharsets.UTF_8));
            writeResponse(out, json == null ? 202 : 200, json); // null = notification, no body
        } catch (Exception ignored) {
            // best-effort: a broken connection must never take down the extension
        }
    }

    private String handleBody(String body) {
        try {
            JsonElement parsed = JsonParser.parseString(body);
            if (parsed.isJsonArray()) {
                JsonArray outArr = new JsonArray();
                for (JsonElement el : parsed.getAsJsonArray()) {
                    JsonObject r = dispatch(el.getAsJsonObject());
                    if (r != null) outArr.add(r);
                }
                return outArr.size() == 0 ? null : gson.toJson(outArr);
            }
            JsonObject r = dispatch(parsed.getAsJsonObject());
            return r == null ? null : gson.toJson(r);
        } catch (Exception e) {
            return gson.toJson(rpcError(null, -32700, "parse error: " + e.getMessage()));
        }
    }

    /** Returns the JSON-RPC response object, or null for notifications (no response). */
    private JsonObject dispatch(JsonObject req) {
        JsonElement id = req.has("id") ? req.get("id") : null;
        String method = req.has("method") ? req.get("method").getAsString() : "";
        JsonObject params = req.has("params") && req.get("params").isJsonObject()
                ? req.getAsJsonObject("params") : new JsonObject();

        switch (method) {
            case "initialize": {
                JsonObject result = new JsonObject();
                String pv = params.has("protocolVersion")
                        ? params.get("protocolVersion").getAsString() : PROTOCOL_VERSION;
                result.addProperty("protocolVersion", pv);
                JsonObject caps = new JsonObject();
                caps.add("tools", new JsonObject());
                result.add("capabilities", caps);
                JsonObject info = new JsonObject();
                info.addProperty("name", "burp-logger-mcp");
                info.addProperty("version", "0.1.0");
                result.add("serverInfo", info);
                return rpcResult(id, result);
            }
            case "notifications/initialized":
            case "notifications/cancelled":
                return null;
            case "ping":
                return rpcResult(id, new JsonObject());
            case "tools/list": {
                JsonObject result = new JsonObject();
                result.add("tools", tools.listTools());
                return rpcResult(id, result);
            }
            case "tools/call": {
                String name = params.has("name") ? params.get("name").getAsString() : "";
                JsonObject args = params.has("arguments") && params.get("arguments").isJsonObject()
                        ? params.getAsJsonObject("arguments") : new JsonObject();
                boolean[] error = {false};
                String text = tools.call(name, args, error);

                JsonObject result = new JsonObject();
                JsonArray content = new JsonArray();
                JsonObject block = new JsonObject();
                block.addProperty("type", "text");
                block.addProperty("text", text);
                content.add(block);
                result.add("content", content);
                result.addProperty("isError", error[0]);
                return rpcResult(id, result);
            }
            default:
                return rpcError(id, -32601, "method not found: " + method);
        }
    }

    private JsonObject rpcResult(JsonElement id, JsonObject result) {
        JsonObject o = new JsonObject();
        o.addProperty("jsonrpc", "2.0");
        o.add("id", id);
        o.add("result", result);
        return o;
    }

    private JsonObject rpcError(JsonElement id, int code, String message) {
        JsonObject o = new JsonObject();
        o.addProperty("jsonrpc", "2.0");
        o.add("id", id);
        JsonObject err = new JsonObject();
        err.addProperty("code", code);
        err.addProperty("message", message);
        o.add("error", err);
        return o;
    }

    // ---- tiny HTTP/1.1 helpers (java.base only) ----

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        int c;
        boolean any = false;
        while ((c = in.read()) != -1) {
            any = true;
            if (c == '\n') break;
            if (c != '\r') buf.write(c);
        }
        if (!any) return null; // stream closed
        return buf.toString(StandardCharsets.ISO_8859_1.name());
    }

    private static byte[] readBytes(InputStream in, int len) throws IOException {
        if (len <= 0) return new byte[0];
        byte[] data = new byte[len];
        int off = 0;
        while (off < len) {
            int n = in.read(data, off, len - off);
            if (n < 0) break;
            off += n;
        }
        return off < len ? Arrays.copyOf(data, off) : data;
    }

    private void writeResponse(OutputStream out, int status, String json) throws IOException {
        byte[] bodyBytes = json == null ? new byte[0] : json.getBytes(StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(status).append(' ').append(reason(status)).append("\r\n");
        if (json != null) sb.append("Content-Type: application/json\r\n");
        sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        sb.append("Mcp-Session-Id: ").append(sessionId).append("\r\n");
        sb.append("Access-Control-Allow-Origin: *\r\n");
        sb.append("Access-Control-Allow-Headers: *\r\n");
        sb.append("Access-Control-Allow-Methods: POST, OPTIONS\r\n");
        sb.append("Connection: close\r\n\r\n");
        out.write(sb.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (bodyBytes.length > 0) out.write(bodyBytes);
        out.flush();
    }

    private static String reason(int status) {
        switch (status) {
            case 200: return "OK";
            case 202: return "Accepted";
            case 204: return "No Content";
            case 405: return "Method Not Allowed";
            default:  return "OK";
        }
    }
}
