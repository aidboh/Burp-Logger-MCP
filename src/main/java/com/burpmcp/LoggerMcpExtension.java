package com.burpmcp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.burpmcp.capture.HttpCaptureHandler;
import com.burpmcp.config.LoggingConfig;
import com.burpmcp.db.LogStore;
import com.burpmcp.mcp.McpHttpServer;
import com.burpmcp.mcp.McpTools;
import com.burpmcp.scan.IssueProvider;
import com.burpmcp.ui.ConfigPanel;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Burp auto-discovers the class implementing BurpExtension in the loaded jar.
 * Load via: Extensions -> Installed -> Add -> Java -> select the shadow jar.
 */
public class LoggerMcpExtension implements BurpExtension {

    private static final int MCP_PORT = 8765;

    private LogStore store;
    private HttpCaptureHandler capture;
    private McpHttpServer mcpServer;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Burp Logger MCP");

        try {
            // Persisted under the user's home so logs survive Burp restarts and project changes.
            Path dbPath = Paths.get(System.getProperty("user.home"), ".burp-logger-mcp", "logs.db");
            store = new LogStore(dbPath, api.logging()::logToOutput);

            LoggingConfig config = new LoggingConfig(store);

            capture = new HttpCaptureHandler(store, config);
            api.http().registerHttpHandler(capture);

            McpTools tools = new McpTools(store, config, new IssueProvider(api));
            mcpServer = new McpHttpServer(MCP_PORT, tools, api.logging()::logToOutput);
            mcpServer.start();

            String url = "http://127.0.0.1:" + MCP_PORT + "/mcp";
            api.userInterface().registerSuiteTab("Logger MCP", new ConfigPanel(store, config, url));

            api.extension().registerUnloadingHandler(this::shutdown);

            api.logging().logToOutput("[burpmcp] ready. DB: " + dbPath + "  MCP: " + url);
        } catch (Exception e) {
            api.logging().logToError("[burpmcp] failed to initialize: " + e);
        }
    }

    private void shutdown() {
        try { if (mcpServer != null) mcpServer.stop(); } catch (Exception ignored) {}
        try { if (capture != null) capture.close(); } catch (Exception ignored) {}
        try { if (store != null) store.close(); } catch (Exception ignored) {}
    }
}
