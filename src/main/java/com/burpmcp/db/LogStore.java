package com.burpmcp.db;

import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.regex.Pattern;

import org.sqlite.Function;

/**
 * Persistent log storage. A single SQLite connection (WAL mode) is shared and guarded by `lock`.
 * Writes are decoupled from Burp's HTTP threads via a queue drained by a dedicated writer thread,
 * which batches inserts in transactions for throughput.
 */
public class LogStore {

    private final Connection conn;
    private final Path dbPath;
    private final Object lock = new Object();
    private final BlockingQueue<LogEntry> queue = new LinkedBlockingQueue<>();
    private final Thread writer;
    private volatile boolean running = true;
    private final Consumer<String> log;

    /** Cache of compiled patterns so REGEXP doesn't recompile per row. */
    private final ConcurrentHashMap<String, Pattern> regexCache = new ConcurrentHashMap<>();

    public LogStore(Path dbPath, Consumer<String> log) throws Exception {
        this.log = log;
        this.dbPath = dbPath;
        Files.createDirectories(dbPath.getParent());
        // sqlite-jdbc registers itself, but be explicit so the driver loads inside Burp's classloader.
        Class.forName("org.sqlite.JDBC");
        this.conn = DriverManager.getConnection("jdbc:sqlite:" + dbPath.toAbsolutePath());
        initSchema();
        registerRegexp();

        this.writer = new Thread(this::drainLoop, "burpmcp-log-writer");
        this.writer.setDaemon(true);
        this.writer.start();
    }

    /**
     * SQLite has the `X REGEXP Y` operator syntax but ships no implementation; it calls a
     * user function regexp(pattern, value). We register one backed by java.util.regex, with
     * a compiled-pattern cache. Patterns can opt into case-insensitivity inline via (?i).
     * Invalid patterns are validated upstream (McpTools), so here a bad pattern just won't match.
     */
    private void registerRegexp() throws SQLException {
        Function.create(conn, "REGEXP", new Function() {
            @Override
            protected void xFunc() throws SQLException {
                String pattern = value_text(0);
                String value = value_text(1);
                if (pattern == null || value == null) { result(0); return; }
                try {
                    Pattern p = regexCache.computeIfAbsent(pattern, Pattern::compile);
                    result(p.matcher(value).find() ? 1 : 0);
                } catch (Exception e) {
                    result(0); // unparseable pattern -> no match
                }
            }
        });
    }

    private void initSchema() throws SQLException {
        synchronized (lock) {
            try (Statement st = conn.createStatement()) {
                st.execute("PRAGMA journal_mode=WAL");
                st.execute("PRAGMA synchronous=NORMAL");
                st.execute("CREATE TABLE IF NOT EXISTS log_entries (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
                        "tool TEXT NOT NULL," +
                        "timestamp INTEGER NOT NULL," +
                        "method TEXT, url TEXT, host TEXT, port INTEGER, protocol TEXT, path TEXT," +
                        "status_code INTEGER," +
                        "request_headers TEXT, request_body TEXT," +
                        "response_headers TEXT, response_body TEXT," +
                        "request_length INTEGER, response_length INTEGER, mime_type TEXT)");
                st.execute("CREATE INDEX IF NOT EXISTS idx_tool ON log_entries(tool)");
                st.execute("CREATE INDEX IF NOT EXISTS idx_ts ON log_entries(timestamp)");
                st.execute("CREATE INDEX IF NOT EXISTS idx_host ON log_entries(host)");
                st.execute("CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT)");
            }
        }
    }

    /** Non-blocking: hand an entry to the writer thread. Called from Burp threads. */
    public void enqueue(LogEntry e) {
        if (running) queue.offer(e);
    }

    private void drainLoop() {
        List<LogEntry> batch = new ArrayList<>();
        while (running || !queue.isEmpty()) {
            try {
                LogEntry first = queue.poll(500, TimeUnit.MILLISECONDS);
                if (first == null) continue;
                batch.clear();
                batch.add(first);
                queue.drainTo(batch, 256);
                flushBatch(batch);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception ex) {
                log.accept("[burpmcp] write error: " + ex);
            }
        }
    }

    private void flushBatch(List<LogEntry> batch) throws SQLException {
        String sql = "INSERT INTO log_entries " +
                "(tool,timestamp,method,url,host,port,protocol,path,status_code," +
                "request_headers,request_body,response_headers,response_body," +
                "request_length,response_length,mime_type) " +
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        synchronized (lock) {
            boolean prevAuto = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                for (LogEntry e : batch) {
                    int i = 1;
                    ps.setString(i++, e.tool);
                    ps.setLong(i++, e.timestamp);
                    ps.setString(i++, e.method);
                    ps.setString(i++, e.url);
                    ps.setString(i++, e.host);
                    ps.setInt(i++, e.port);
                    ps.setString(i++, e.protocol);
                    ps.setString(i++, e.path);
                    if (e.statusCode == null) ps.setNull(i++, java.sql.Types.INTEGER); else ps.setInt(i++, e.statusCode);
                    ps.setString(i++, e.requestHeaders);
                    ps.setString(i++, e.requestBody);
                    ps.setString(i++, e.responseHeaders);
                    ps.setString(i++, e.responseBody);
                    if (e.requestLength == null) ps.setNull(i++, java.sql.Types.INTEGER); else ps.setInt(i++, e.requestLength);
                    if (e.responseLength == null) ps.setNull(i++, java.sql.Types.INTEGER); else ps.setInt(i++, e.responseLength);
                    ps.setString(i++, e.mimeType);
                    ps.addBatch();
                }
                ps.executeBatch();
                conn.commit();
            } catch (SQLException ex) {
                conn.rollback();
                throw ex;
            } finally {
                conn.setAutoCommit(prevAuto);
            }
        }
    }

    // ---- Queries (called from MCP threads) ----

    /** Summary list with optional filters. Bodies/headers are NOT included here (use getById). */
    public List<Map<String, Object>> query(String tool, String host, String method, Integer status,
                                            String search, String regex, Long since, Long until,
                                            int limit, int offset) {
        StringBuilder sb = new StringBuilder(
                "SELECT id,tool,timestamp,method,url,host,port,protocol,status_code," +
                "request_length,response_length,mime_type FROM log_entries WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (tool != null)   { sb.append(" AND tool=?");   args.add(tool); }
        if (host != null)   { sb.append(" AND host LIKE ?"); args.add("%" + host + "%"); }
        if (method != null) { sb.append(" AND method=?"); args.add(method); }
        if (status != null) { sb.append(" AND status_code=?"); args.add(status); }
        if (since != null)  { sb.append(" AND timestamp>=?"); args.add(since); }
        if (until != null)  { sb.append(" AND timestamp<=?"); args.add(until); }
        if (search != null) {
            sb.append(" AND (url LIKE ? OR request_headers LIKE ? OR request_body LIKE ? " +
                      "OR response_headers LIKE ? OR response_body LIKE ?)");
            String s = "%" + search + "%";
            for (int k = 0; k < 5; k++) args.add(s);
        }
        if (regex != null) {
            sb.append(" AND (url REGEXP ? OR request_headers REGEXP ? OR request_body REGEXP ? " +
                      "OR response_headers REGEXP ? OR response_body REGEXP ?)");
            for (int k = 0; k < 5; k++) args.add(regex);
        }
        sb.append(" ORDER BY id DESC LIMIT ? OFFSET ?");
        args.add(Math.max(1, Math.min(limit, 1000)));
        args.add(Math.max(0, offset));

        List<Map<String, Object>> out = new ArrayList<>();
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(sb.toString())) {
                bind(ps, args);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Map<String, Object> m = new LinkedHashMap<>();
                        m.put("id", rs.getLong("id"));
                        m.put("tool", rs.getString("tool"));
                        m.put("timestamp", rs.getLong("timestamp"));
                        m.put("method", rs.getString("method"));
                        m.put("url", rs.getString("url"));
                        m.put("host", rs.getString("host"));
                        m.put("port", rs.getInt("port"));
                        m.put("protocol", rs.getString("protocol"));
                        Object sc = rs.getObject("status_code");
                        m.put("status_code", sc);
                        m.put("request_length", rs.getObject("request_length"));
                        m.put("response_length", rs.getObject("response_length"));
                        m.put("mime_type", rs.getString("mime_type"));
                        out.add(m);
                    }
                }
            } catch (SQLException ex) {
                log.accept("[burpmcp] query error: " + ex);
            }
        }
        return out;
    }

    public Map<String, Object> getById(long id, int maxBodyChars) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM log_entries WHERE id=?")) {
                ps.setLong(1, id);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? rowToFull(rs, maxBodyChars) : null;
                }
            } catch (SQLException ex) {
                log.accept("[burpmcp] getById error: " + ex);
                return null;
            }
        }
    }

    /**
     * Batch fetch: full entries (headers + bodies) for many ids in one query, returned keyed by
     * id so the caller can reassemble in whatever order it likes. Lets an agent pull every entry
     * it cares about in a single round-trip instead of one get_log_entry call per id.
     */
    public Map<Long, Map<String, Object>> getByIds(List<Long> ids, int maxBodyChars) {
        Map<Long, Map<String, Object>> out = new LinkedHashMap<>();
        if (ids == null || ids.isEmpty()) return out;
        StringBuilder ph = new StringBuilder();
        for (int k = 0; k < ids.size(); k++) ph.append(k == 0 ? "?" : ",?");
        String sql = "SELECT * FROM log_entries WHERE id IN (" + ph + ")";
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                for (int k = 0; k < ids.size(); k++) ps.setLong(k + 1, ids.get(k));
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) out.put(rs.getLong("id"), rowToFull(rs, maxBodyChars));
                }
            } catch (SQLException ex) {
                log.accept("[burpmcp] getByIds error: " + ex);
            }
        }
        return out;
    }

    /** Maps a full row (all columns, bodies truncated to maxBodyChars) into an ordered map. */
    private static Map<String, Object> rowToFull(ResultSet rs, int maxBodyChars) throws SQLException {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", rs.getLong("id"));
        m.put("tool", rs.getString("tool"));
        m.put("timestamp", rs.getLong("timestamp"));
        m.put("method", rs.getString("method"));
        m.put("url", rs.getString("url"));
        m.put("host", rs.getString("host"));
        m.put("port", rs.getInt("port"));
        m.put("protocol", rs.getString("protocol"));
        m.put("path", rs.getString("path"));
        m.put("status_code", rs.getObject("status_code"));
        m.put("request_headers", rs.getString("request_headers"));
        m.put("request_body", truncate(rs.getString("request_body"), maxBodyChars));
        m.put("response_headers", rs.getString("response_headers"));
        m.put("response_body", truncate(rs.getString("response_body"), maxBodyChars));
        m.put("request_length", rs.getObject("request_length"));
        m.put("response_length", rs.getObject("response_length"));
        m.put("mime_type", rs.getString("mime_type"));
        return m;
    }

    /** Purge by tool and/or age. Returns rows deleted. */
    public int purge(String tool, Long beforeTimestamp) {
        StringBuilder sb = new StringBuilder("DELETE FROM log_entries WHERE 1=1");
        List<Object> args = new ArrayList<>();
        if (tool != null)             { sb.append(" AND tool=?"); args.add(tool); }
        if (beforeTimestamp != null)  { sb.append(" AND timestamp<?"); args.add(beforeTimestamp); }
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(sb.toString())) {
                bind(ps, args);
                int n = ps.executeUpdate();
                try (Statement st = conn.createStatement()) {
                    st.execute("PRAGMA wal_checkpoint(TRUNCATE)");
                    // Full purge (Purge ALL): rebuild the file so freed pages are returned to the OS,
                    // not just marked reusable. Cheap here because the table is now empty.
                    if (tool == null && beforeTimestamp == null) {
                        st.execute("VACUUM");
                    }
                }
                return n;
            } catch (SQLException ex) {
                log.accept("[burpmcp] purge error: " + ex);
                return -1;
            }
        }
    }

    public Map<String, Object> stats() {
        Map<String, Object> out = new LinkedHashMap<>();
        Map<String, Object> byTool = new LinkedHashMap<>();
        synchronized (lock) {
            try (Statement st = conn.createStatement()) {
                try (ResultSet rs = st.executeQuery("SELECT tool,COUNT(*) c FROM log_entries GROUP BY tool")) {
                    while (rs.next()) byTool.put(rs.getString(1), rs.getLong(2));
                }
                try (ResultSet rs = st.executeQuery(
                        "SELECT COUNT(*),MIN(timestamp),MAX(timestamp) FROM log_entries")) {
                    if (rs.next()) {
                        out.put("total", rs.getLong(1));
                        out.put("earliest", rs.getObject(2));
                        out.put("latest", rs.getObject(3));
                    }
                }
            } catch (SQLException ex) {
                log.accept("[burpmcp] stats error: " + ex);
            }
        }
        out.put("by_tool", byTool);
        long bytes = dbSizeBytes();
        out.put("db_bytes", bytes);
        out.put("db_size", humanBytes(bytes));
        return out;
    }

    /** On-disk size of the store: the .db file plus its WAL/SHM sidecars (0 if not yet created). */
    public long dbSizeBytes() {
        long total = 0;
        for (String suffix : new String[]{"", "-wal", "-shm"}) {
            try {
                Path p = dbPath.resolveSibling(dbPath.getFileName().toString() + suffix);
                if (Files.exists(p)) total += Files.size(p);
            } catch (Exception ignored) {}
        }
        return total;
    }

    /** Formats a byte count as B / KB / MB / GB. */
    public static String humanBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        String[] units = {"KB", "MB", "GB", "TB"};
        double v = bytes;
        int i = -1;
        do { v /= 1024.0; i++; } while (v >= 1024 && i < units.length - 1);
        return String.format("%.1f %s", v, units[i]);
    }

    // ---- Config (per-tool logging toggles, etc.) ----

    public String getConfig(String key) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement("SELECT value FROM config WHERE key=?")) {
                ps.setString(1, key);
                try (ResultSet rs = ps.executeQuery()) { return rs.next() ? rs.getString(1) : null; }
            } catch (SQLException ex) { return null; }
        }
    }

    public void setConfig(String key, String value) {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO config(key,value) VALUES(?,?) " +
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value")) {
                ps.setString(1, key);
                ps.setString(2, value);
                ps.executeUpdate();
            } catch (SQLException ex) {
                log.accept("[burpmcp] setConfig error: " + ex);
            }
        }
    }

    public void close() {
        running = false;
        try { writer.join(3000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        synchronized (lock) {
            try { conn.close(); } catch (SQLException ignored) {}
        }
    }

    private static void bind(PreparedStatement ps, List<Object> args) throws SQLException {
        for (int i = 0; i < args.size(); i++) ps.setObject(i + 1, args.get(i));
    }

    private static String truncate(String s, int max) {
        if (s == null || max <= 0 || s.length() <= max) return s;
        return s.substring(0, max) + "\n...[truncated " + (s.length() - max) + " chars]";
    }
}
