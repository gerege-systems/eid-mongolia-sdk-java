package mn.eidmongolia.eid;

import java.net.URI;
import java.time.Duration;
import java.util.Map;

/**
 * One RP-API request ({@link EidTransport}).
 *
 * @param method "GET" or "POST"
 * @param uri the full URL (base URL + path)
 * @param headers request headers (Authorization, Content-Type, Accept-Language); never log them — Authorization
 *     carries the API secret
 * @param body the request body, or null (GET)
 * @param timeout the deadline for the whole exchange
 * @param maxResponseBytes read at most this many body bytes + 1
 */
public record EidHttpRequest(String method, URI uri, Map<String, String> headers, byte[] body, Duration timeout,
    long maxResponseBytes) {
    public EidHttpRequest {
        headers = Map.copyOf(headers);
    }

    /** No headers or body in the text (the Authorization header holds the API secret). */
    @Override
    public String toString() {
        return "EidHttpRequest[" + method + " " + EidException.maskPath(uri.getRawPath() == null ? "" : uri.getRawPath()) + "]";
    }
}
