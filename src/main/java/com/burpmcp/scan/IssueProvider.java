package com.burpmcp.scan;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.sitemap.SiteMap;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Exposes Burp Scanner findings (audit issues) to the MCP layer.
 *
 * Issues are queried LIVE from the site map on every call rather than persisted: Burp already
 * stores them in the project, they're low-volume, and live reads avoid staleness. Note that
 * audit issues only exist in Burp editions that include Scanner (Pro/DAST); on Community,
 * siteMap().issues() simply returns an empty list.
 *
 * Each issue gets a stable short id derived from its name/url/severity/confidence so that
 * get(id) can re-resolve the same finding across calls without relying on list ordering.
 */
public class IssueProvider {

    private final SiteMap siteMap;

    public IssueProvider(MontoyaApi api) {
        this.siteMap = api.siteMap();
    }

    /** Summary rows, highest severity first, with optional filters. */
    public List<Map<String, Object>> list(String severity, String confidence, String host, int limit) {
        List<AuditIssue> issues = new ArrayList<>(siteMap.issues());
        issues.sort(Comparator.comparingInt(IssueProvider::severityRank));

        List<Map<String, Object>> out = new ArrayList<>();
        for (AuditIssue is : issues) {
            if (severity != null && !is.severity().name().equalsIgnoreCase(severity)) continue;
            if (confidence != null && !is.confidence().name().equalsIgnoreCase(confidence)) continue;
            String h = hostOf(is);
            if (host != null && (h == null || !h.toLowerCase().contains(host.toLowerCase()))) continue;

            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", issueId(is));
            m.put("name", is.name());
            m.put("severity", is.severity().name());
            m.put("confidence", is.confidence().name());
            m.put("base_url", nullSafe(is.baseUrl()));
            m.put("host", h);
            List<HttpRequestResponse> rrs = is.requestResponses();
            m.put("evidence_count", rrs == null ? 0 : rrs.size());
            out.add(m);
            if (out.size() >= Math.max(1, limit)) break;
        }
        return out;
    }

    /** Full detail for one finding, including remediation and the request/response evidence. */
    public Map<String, Object> get(String id, int maxBodyChars) {
        if (id == null) return null;
        for (AuditIssue is : siteMap.issues()) {
            if (issueId(is).equals(id)) return detail(is, maxBodyChars);
        }
        return null;
    }

    /** Counts by severity, for a quick overview. */
    public Map<String, Object> summary() {
        Map<String, Object> bySeverity = new LinkedHashMap<>();
        int total = 0;
        for (AuditIssue is : siteMap.issues()) {
            String sev = is.severity().name();
            bySeverity.merge(sev, 1L, (a, b) -> ((Long) a) + 1L);
            total++;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("total", total);
        out.put("by_severity", bySeverity);
        return out;
    }

    private Map<String, Object> detail(AuditIssue is, int maxBodyChars) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", issueId(is));
        m.put("name", is.name());
        m.put("severity", is.severity().name());
        m.put("confidence", is.confidence().name());
        m.put("base_url", nullSafe(is.baseUrl()));
        m.put("host", hostOf(is));
        m.put("detail", is.detail());
        m.put("remediation", is.remediation());
        try {
            if (is.definition() != null) {
                m.put("background", is.definition().background());
                m.put("remediation_background", is.definition().remediation());
            }
        } catch (Exception ignored) {}

        List<Map<String, Object>> evidence = new ArrayList<>();
        List<HttpRequestResponse> rrs = is.requestResponses();
        if (rrs != null) {
            for (HttpRequestResponse rr : rrs) evidence.add(renderEvidence(rr, maxBodyChars));
        }
        m.put("evidence", evidence);
        return m;
    }

    private Map<String, Object> renderEvidence(HttpRequestResponse rr, int maxBodyChars) {
        Map<String, Object> e = new LinkedHashMap<>();
        try {
            if (rr.request() != null) {
                Map<String, Object> req = new LinkedHashMap<>();
                req.put("method", rr.request().method());
                req.put("url", rr.request().url());
                req.put("headers", headersToString(rr.request().headers()));
                req.put("body", truncate(rr.request().bodyToString(), maxBodyChars));
                e.put("request", req);
            }
        } catch (Exception ignored) {}
        try {
            if (rr.response() != null) {
                Map<String, Object> resp = new LinkedHashMap<>();
                resp.put("status_code", (int) rr.response().statusCode());
                resp.put("headers", headersToString(rr.response().headers()));
                resp.put("body", truncate(rr.response().bodyToString(), maxBodyChars));
                e.put("response", resp);
            }
        } catch (Exception ignored) {}
        return e;
    }

    // ---- helpers ----

    private static int severityRank(AuditIssue i) {
        switch (i.severity()) {
            case HIGH:        return 0;
            case MEDIUM:      return 1;
            case LOW:         return 2;
            case INFORMATION: return 3;
            default:          return 4; // FALSE_POSITIVE
        }
    }

    private static String hostOf(AuditIssue i) {
        try {
            if (i.httpService() != null) return i.httpService().host();
        } catch (Exception ignored) {}
        return null;
    }

    private static String issueId(AuditIssue i) {
        String basis = nullSafe(i.name()) + "|" + nullSafe(i.baseUrl()) + "|"
                + i.severity().name() + "|" + i.confidence().name();
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(basis.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < 6; k++) sb.append(String.format("%02x", d[k]));
            return sb.toString();
        } catch (Exception e) {
            return Integer.toHexString(basis.hashCode());
        }
    }

    private static String headersToString(List<HttpHeader> headers) {
        if (headers == null) return null;
        StringBuilder sb = new StringBuilder();
        for (HttpHeader h : headers) sb.append(h.name()).append(": ").append(h.value()).append('\n');
        return sb.toString();
    }

    private static String nullSafe(String s) { return s == null ? "" : s; }

    private static String truncate(String s, int max) {
        if (s == null || max <= 0 || s.length() <= max) return s;
        return s.substring(0, max) + "\n...[truncated " + (s.length() - max) + " chars]";
    }
}
