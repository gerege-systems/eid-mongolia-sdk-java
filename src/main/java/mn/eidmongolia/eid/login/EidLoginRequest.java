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

    /** The first value of a header (case-insensitive), else "". */
    public String header(String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() || v.get(0) == null ? "" : v.get(0);
    }

    /** A cookie's value from the Cookie header(s) (first match), else "" (TS {@code readCookie}). */
    String cookie(String name) {
        List<String> all = headers.get("Cookie");
        if (all == null) return "";
        for (String line : all) {
            for (String part : line.split(";")) {
                int i = part.indexOf('=');
                if (i > 0 && part.substring(0, i).trim().equals(name)) return part.substring(i + 1).trim();
            }
        }
        return "";
    }

    String lowerMethod() {
        return method.toUpperCase(Locale.ROOT);
    }
}
