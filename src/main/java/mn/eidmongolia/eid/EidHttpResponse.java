package mn.eidmongolia.eid;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * One RP-API response ({@link EidTransport}).
 *
 * @param status the HTTP status
 * @param headers response headers (any case; looked up case-insensitively)
 * @param body the body — at most {@link EidHttpRequest#maxResponseBytes()} + 1 bytes; empty when there is none
 */
public record EidHttpResponse(int status, Map<String, List<String>> headers, byte[] body) {
    public EidHttpResponse {
        headers = headers == null ? Map.of() : headers;
        body = body == null ? new byte[0] : body;
    }

    /** The first value of a header (case-insensitive), else null. */
    public String header(String name) {
        for (Map.Entry<String, List<String>> e : headers.entrySet()) {
            if (e.getKey() != null && e.getKey().toLowerCase(Locale.ROOT).equals(name.toLowerCase(Locale.ROOT))
                && e.getValue() != null && !e.getValue().isEmpty()) {
                return e.getValue().get(0);
            }
        }
        return null;
    }
}
