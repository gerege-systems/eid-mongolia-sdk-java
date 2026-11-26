package mn.eidmongolia.eid.login;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * A framework-neutral HTTP request for {@link EidLogin#handle} (TS {@code EidLoginRequest}).
 *
 * @param method GET | POST …
 * @param url the path with its query ({@code /auth/eid/status?…}) or a full URL
 * @param headers header name (any case) → values
 * @param body the raw body (POST /start); null or empty otherwise
 * @param ip the client IP for the {@code start:<ip>} rate limit, already derived by the adapter from the socket or from
 *     TRUSTED proxies only ({@link EidLogin#forwardedClientIp}); null / "" = unknown (no per-IP limit)
 */
public record EidLoginRequest(String method, String url, Map<String, List<String>> headers, byte[] body, String ip) {

    public EidLoginRequest {
        method = method == null ? "" : method;
        url = url == null ? "" : url;
        Map<String, List<String>> h = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        if (headers != null) {
            for (Map.Entry<String, List<String>> e : headers.entrySet()) {
                if (e.getKey() == null || e.getValue() == null) continue;
                h.computeIfAbsent(e.getKey(), k -> new java.util.ArrayList<>()).addAll(e.getValue());
            }
        }
        h.replaceAll((k, v) -> List.copyOf(v));
        headers = Collections.unmodifiableMap(h);
        body = body == null ? new byte[0] : body.clone();
    }

    /** A request with a UTF-8 text body (tests, simple adapters). */
    public static EidLoginRequest of(String method, String url, Map<String, List<String>> headers, String body, String ip) {
        return new EidLoginRequest(method, url, headers, body == null ? null : body.getBytes(StandardCharsets.UTF_8), ip);
    }

    @Override
    public byte[] body() {
        return body.clone();
    }

    byte[] rawBody() {
        return body;
    }

    /**
     * Redacted: the path without its query (the callback's userChallengeVerifier), header NAMES only (no Cookie /
     * Authorization values) and the body's length — safe for logs.
     */
    @Override
    public String toString() {
        int q = url.indexOf('?');
        return "EidLoginRequest[method=" + method + ", url=" + (q < 0 ? url : url.substring(0, q) + "?…") + ", headers=" + headers.keySet()
            + ", body=" + body.length + " bytes, ip=" + ip + "]";
    }

    /** The first value of a header (case-insensitive), else "". */
    public String header(String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() || v.get(0) == null ? "" : v.get(0);
    }

    /**
     * A cookie's value when the Cookie header(s) carry EXACTLY ONE part with that name, else "" (rp-conformance/2, Go
     * {@code singleCookie}, TS {@code readCookie}): every header split on ";", each part trimmed, name = text before the
     * first "=" (trimmed), value = the rest (trimmed). Two or more parts with the name — whatever their values — count as
     * no cookie, so a cookie planted from a sibling host or another path cannot shadow the real one.
     */
    String cookie(String name) {
        List<String> all = headers.get("Cookie");
        if (all == null) return "";
        String value = "";
        int n = 0;
        for (String line : all) {
            if (line == null) continue;
            for (String part : line.split(";", -1)) {
                String p = part.trim();
                int i = p.indexOf('=');
                if (i < 0 || !p.substring(0, i).trim().equals(name)) continue;
                value = p.substring(i + 1).trim();
                n++;
            }
        }
        return n == 1 ? value : "";
    }

    String lowerMethod() {
        return method.toUpperCase(Locale.ROOT);
    }
}
