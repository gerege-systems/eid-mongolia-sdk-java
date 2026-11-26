package mn.eidmongolia.eid.login;

import java.util.List;
import java.util.Map;

/**
 * {@link EidLogin#handle}'s answer (TS {@code EidLoginResponse}): write the status, every header value (Set-Cookie may
 * repeat) and the body as is. Redirects (302 / 303) have an empty body.
 */
public record EidLoginResponse(int status, Map<String, List<String>> headers, String body) {

    /** The first value of a header (exact name as the handler sets it), else null. */
    public String header(String name) {
        List<String> v = headers.get(name);
        return v == null || v.isEmpty() ? null : v.get(0);
    }
}
