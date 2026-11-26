package mn.eidmongolia.eid;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;

/** A session start response (Go {@code sessionStartResponse}). Absent strings are "". */
final class StartResponse {
    final String sessionId;
    final String sessionToken;
    final String sessionSecret;
    final String deviceLinkBase;
    final String vc;
    /** The CA's expiresAt (RFC 3339, CA 2026-10-14); null when absent or unparseable (older CA). */
    final Instant caExpiresAt;

    private StartResponse(Json.Obj o) {
        sessionId = o.optString("sessionID");
        sessionToken = o.optString("sessionToken");
        sessionSecret = o.optString("sessionSecret");
        deviceLinkBase = o.optString("deviceLinkBase");
        vc = vcOf(o.get("vc"));
        caExpiresAt = parseRfc3339(o.optString("expiresAt"));
    }

    static StartResponse of(RpHttp.Result r, String op) {
        return new StartResponse(r.obj(op));
    }

    /** Go {@code vcValue}: vc is a string (device link) or a {"type","value"} object (notification). */
    static String vcOf(Object v) {
        if (v instanceof String) return (String) v;
        if (v instanceof Json.Obj) return ((Json.Obj) v).optString("value");
        return "";
    }

    /** sign / certificate choice: the CA's expiresAt, else {@link EidClient#sessionExpiry}(sent, ttl) (Go {@code expiresAt}). */
    Instant expiresAt(Instant sent, Duration ttl) {
        return caExpiresAt != null ? caExpiresAt : EidClient.sessionExpiry(sent, ttl);
    }

    static Instant parseRfc3339(String s) {
        if (s == null || s.isEmpty()) return null;
        try {
            return OffsetDateTime.parse(s, DateTimeFormatter.ISO_OFFSET_DATE_TIME).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
