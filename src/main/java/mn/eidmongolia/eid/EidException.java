package mn.eidmongolia.eid;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * Base of every RP-API client error (TS {@code EidError}, Go {@code errors.go}). Catch the subclasses to choose the
 * right reaction: {@link Authentication} → configuration (API secret), {@link SessionFailed} with
 * {@code USER_REFUSED} → try again, {@link Validation} → do NOT trust the response.
 *
 * <p>{@link #code()}, {@link #status()}, {@link #retryAfter()} and {@link #retryable()} are defined on every error
 * (empty / 0 / {@link Duration#ZERO} / false when they do not apply), so a handler can branch without casting.
 * Messages and {@link Network#op()} never contain personal identifiers: the path segments after
 * {@code /etsi/}, {@code /document/}, {@code /linked/}, {@code /requests/}, {@code /seal/[certificate/|grants/]} are
 * replaced by "…" ({@link #maskPath}).
 */
public class EidException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    EidException(String message) {
        super(message);
    }

    EidException(String message, Throwable cause) {
        super(message, cause);
    }

    /** The server's stable error code ({@link EidErrorCodes}); "" when there is none. */
    public String code() {
        return "";
    }

    /** The HTTP status; 0 when the error did not come from an HTTP response. */
    public int status() {
        return 0;
    }

    /** The response's Retry-After (delay-seconds or HTTP-date); {@link Duration#ZERO} when absent or invalid. */
    public Duration retryAfter() {
        return Duration.ZERO;
    }

    /** True when the same request may be repeated after {@link #retryAfter()} (temporary CA error). */
    public boolean retryable() {
        return false;
    }

    /** Response headers, keys lower-case. */
    static Map<String, List<String>> headerMap(Map<String, List<String>> h) {
        Map<String, List<String>> m = new TreeMap<>();
        if (h != null) {
            for (Map.Entry<String, List<String>> e : h.entrySet()) {
                if (e.getKey() == null) continue;
                m.computeIfAbsent(e.getKey().toLowerCase(Locale.ROOT), k -> new java.util.ArrayList<>()).addAll(e.getValue());
            }
        }
        m.replaceAll((k, v) -> List.copyOf(v));
        return Collections.unmodifiableMap(m);
    }

    /** Base of the HTTP status errors ({@link Authentication}, {@link Forbidden}, {@link Api}). */
    public abstract static class Http extends EidException {
        private static final long serialVersionUID = 1L;
        private final int status;
        private final String code;
        private final String serverMessage;
        private final String body;
        private final Duration retryAfter;
        private final transient Map<String, List<String>> headers;

        Http(String message, int status, String code, String serverMessage, String body, Duration retryAfter,
            Map<String, List<String>> headers) {
            super(message);
            this.status = status;
            this.code = code == null ? "" : code;
            this.serverMessage = serverMessage == null ? "" : serverMessage;
            this.body = body == null ? "" : body;
            this.retryAfter = retryAfter == null ? Duration.ZERO : retryAfter;
            this.headers = headerMap(headers);
        }

        @Override
        public int status() {
            return status;
        }

        @Override
        public String code() {
            return code;
        }

        /** The server's {@code {"error"}} text (for logs — not for end users); "" when the body is not CA JSON. */
        public String serverMessage() {
            return serverMessage;
        }

        /** The response body (truncated to 64 KiB). */
        public String body() {
            return body;
        }

        @Override
        public Duration retryAfter() {
            return retryAfter;
        }

        /** Response headers (lower-case names). */
        public Map<String, List<String>> headers() {
            return headers == null ? Map.of() : headers;
        }

        /** The first value of a response header (case-insensitive), else null. */
        public String header(String name) {
            List<String> v = headers().get(name.toLowerCase(Locale.ROOT));
            return v == null || v.isEmpty() ? null : v.get(0);
        }
    }

    /**
     * HTTP 401 — API secret wrong or missing (configuration error). The CA's own 401 is JSON
     * {@code {"error"[,"code"]}}: {@link #serverMessage()} (and {@link #code()}) are set; a proxy's non-JSON 401 leaves
     * both empty.
     */
    public static final class Authentication extends Http {
        private static final long serialVersionUID = 1L;

        Authentication(String code, String serverMessage, String body, Map<String, List<String>> headers) {
            super(code == null || code.isEmpty() ? "eid: API secret буруу эсвэл байхгүй (401)"
                : "eid: API secret буруу эсвэл байхгүй (401 " + code + ")", 401, code, serverMessage, body, Duration.ZERO, headers);
        }
    }

    /**
     * HTTP 403 — IP allowlist / mTLS not allowed, the RP lacks the permission, or onBehalfOf representation refused.
     * {@link #code()} carries the server's code (e.g. {@link EidErrorCodes#REPRESENTATION_DENIED}) when it sent one.
     */
    public static final class Forbidden extends Http {
        private static final long serialVersionUID = 1L;

        Forbidden(String code, String serverMessage, String body, Duration retryAfter, Map<String, List<String>> headers) {
            super(message(code, serverMessage), 403, code, serverMessage, body, retryAfter, headers);
        }

        private static String message(String code, String msg) {
            if (msg == null || msg.isEmpty()) return "eid: IP allowlist эсвэл mTLS зөвшөөрөөгүй (403)";
            if (code != null && !code.isEmpty()) return "eid: RP-API 403 " + code + ": " + msg;
            return "eid: RP-API 403: " + msg;
        }
    }

    /** Any other RP-API HTTP error (4xx/5xx). Known codes come as the subclasses below. */
    public static class Api extends Http {
        private static final long serialVersionUID = 1L;
        private final String service;

        Api(int status, String code, String serverMessage, String body, String service, Duration retryAfter,
            Map<String, List<String>> headers) {
            super("eid: RP-API " + status + ": " + (body == null ? "" : body), status, code, serverMessage, body, retryAfter, headers);
            this.service = service == null ? "" : service;
        }

        /** The server's {@code {"service"}} — for {@link EidErrorCodes#SEAL_SERVICE_DISABLED}: "issuance" | "sealing"; else "". */
        public String service() {
            return service;
        }

        /**
         * A temporary CA error ({@link EidErrorCodes#RETRYABLE}, or 429/503 with Retry-After): repeat the same request
         * after {@link #retryAfter()}. {@link EidErrorCodes#SEAL_SERVICE_DISABLED} — never (Go {@code APIError.Retryable}).
         */
        @Override
        public boolean retryable() {
            if (code().equals(EidErrorCodes.SEAL_SERVICE_DISABLED)) return false;
            if (EidErrorCodes.RETRYABLE.contains(code())) return true;
            return (status() == 429 || status() == 503) && retryAfter().compareTo(Duration.ZERO) > 0;
        }
    }

    /** 409 NO_SIGNING_CERTIFICATE — no device / SIGN credential / valid signing certificate. No session was created. */
    public static final class NoSigningCertificate extends Api {
        private static final long serialVersionUID = 1L;

        NoSigningCertificate(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 CERT_CHOICE_INVALID — restart the certificate choice. */
    public static final class CertChoiceInvalid extends Api {
        private static final long serialVersionUID = 1L;

        CertChoiceInvalid(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 400 REQUEST_INVALID — a programming error. */
    public static final class RequestInvalid extends Api {
        private static final long serialVersionUID = 1L;

        RequestInvalid(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 404 QR_TOKEN_INVALID («My QR») — have the citizen show a new QR. */
    public static final class QrTokenInvalid extends Api {
        private static final long serialVersionUID = 1L;

        QrTokenInvalid(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 ORG_NOT_ACTIVE (seal routes). The onBehalfOf 403 ORG_NOT_ACTIVE stays a {@link Forbidden}. */
    public static final class OrgNotActive extends Api {
        private static final long serialVersionUID = 1L;

        OrgNotActive(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_NOT_ISSUED. */
    public static final class SealNotIssued extends Api {
        private static final long serialVersionUID = 1L;

        SealNotIssued(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_CERT_REVOKED. */
    public static final class SealCertRevoked extends Api {
        private static final long serialVersionUID = 1L;

        SealCertRevoked(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_KEY_UNAVAILABLE. */
    public static final class SealKeyUnavailable extends Api {
        private static final long serialVersionUID = 1L;

        SealKeyUnavailable(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_CERT_EXPIRED. */
    public static final class SealCertExpired extends Api {
        private static final long serialVersionUID = 1L;

        SealCertExpired(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_CERT_NOT_YET_VALID. */
    public static final class SealCertNotYetValid extends Api {
        private static final long serialVersionUID = 1L;

        SealCertNotYetValid(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_APPROVER_UNAVAILABLE. */
    public static final class SealApproverUnavailable extends Api {
        private static final long serialVersionUID = 1L;

        SealApproverUnavailable(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 404 SEAL_REQUEST_NOT_FOUND. */
    public static final class SealRequestNotFound extends Api {
        private static final long serialVersionUID = 1L;

        SealRequestNotFound(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /**
     * 503 SEAL_SERVICE_DISABLED — the operator switched the seal service off. {@link #retryable()} is always false,
     * even when a proxy added Retry-After. {@link #service()}: "issuance" | "sealing".
     */
    public static final class SealServiceDisabled extends Api {
        private static final long serialVersionUID = 1L;

        SealServiceDisabled(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 AUTH_SESSION_WRONG_FLOW (seal grant request). */
    public static final class AuthSessionWrongFlow extends Api {
        private static final long serialVersionUID = 1L;

        AuthSessionWrongFlow(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 AUTH_SESSION_NOT_COMPLETED (seal grant request). */
    public static final class AuthSessionNotCompleted extends Api {
        private static final long serialVersionUID = 1L;

        AuthSessionNotCompleted(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 AUTH_SESSION_TOO_OLD (seal grant request). */
    public static final class AuthSessionTooOld extends Api {
        private static final long serialVersionUID = 1L;

        AuthSessionTooOld(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 AUTH_SESSION_ALREADY_USED (seal grant request). */
    public static final class AuthSessionAlreadyUsed extends Api {
        private static final long serialVersionUID = 1L;

        AuthSessionAlreadyUsed(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 404 AUTH_SESSION_NOT_FOUND (seal grant request). */
    public static final class AuthSessionNotFound extends Api {
        private static final long serialVersionUID = 1L;

        AuthSessionNotFound(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 SEAL_GRANT_ALREADY_APPROVED. */
    public static final class SealGrantAlreadyApproved extends Api {
        private static final long serialVersionUID = 1L;

        SealGrantAlreadyApproved(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 404 SEAL_GRANT_NOT_FOUND. */
    public static final class SealGrantNotFound extends Api {
        private static final long serialVersionUID = 1L;

        SealGrantNotFound(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 RP_NOT_ACTIVE. */
    public static final class RpNotActive extends Api {
        private static final long serialVersionUID = 1L;

        RpNotActive(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /** 409 RP_PERMISSIONS_FULL. */
    public static final class RpPermissionsFull extends Api {
        private static final long serialVersionUID = 1L;

        RpPermissionsFull(int s, String c, String m, String b, String sv, Duration r, Map<String, List<String>> h) {
            super(s, c, m, b, sv, r, h);
        }
    }

    /**
     * Network failure or timeout: the upstream gave no response. {@link #op()} is "METHOD masked-path". Cancellation
     * by {@link Thread#interrupt()} also ends here ({@link #cancelled()}); the thread's interrupt flag stays set.
     */
    public static final class Network extends EidException {
        private static final long serialVersionUID = 1L;
        private final String op;
        private final boolean timeout;
        private final boolean cancelled;

        Network(String op, boolean timeout, boolean cancelled, Throwable cause) {
            super(timeout ? "eid: хүсэлт хугацаа хэтэрлээ: " + op
                : cancelled ? "eid: хүсэлт цуцлагдлаа (interrupt): " + op
                : "eid: сүлжээний алдаа (" + op + "): " + causeText(cause), cause);
            this.op = op;
            this.timeout = timeout;
            this.cancelled = cancelled;
        }

        private static String causeText(Throwable t) {
            if (t == null) return "";
            String m = t.getMessage();
            return t.getClass().getSimpleName() + (m == null ? "" : ": " + m);
        }

        /** "GET /session/…" — identifiers masked. */
        public String op() {
            return op;
        }

        /** The request's deadline passed. */
        public boolean timeout() {
            return timeout;
        }

        /** The calling thread was interrupted. */
        public boolean cancelled() {
            return cancelled;
        }
    }

    /** The response body exceeds the SDK limit (JSON 4 MiB); it is not truncated and parsed. */
    public static final class ResponseTooLarge extends EidException {
        private static final long serialVersionUID = 1L;
        private final String op;
        private final long limit;

        ResponseTooLarge(String op, long limit) {
            super("eid: " + op + ": хариу " + limit + " байтаас их");
            this.op = op;
            this.limit = limit;
        }

        public String op() {
            return op;
        }

        public long limit() {
            return limit;
        }
    }

    /** The session ended without success (endResult ≠ OK): TIMEOUT, USER_REFUSED*, DOCUMENT_UNUSABLE, … */
    public static final class SessionFailed extends EidException {
        private static final long serialVersionUID = 1L;
        private final String endResult;

        SessionFailed(String endResult) {
            super("eid: session амжилтгүй: " + endResult);
            this.endResult = endResult;
        }

        public String endResult() {
            return endResult;
        }

        /** The endResult (e.g. USER_REFUSED). */
        @Override
        public String code() {
            return endResult;
        }
    }

    /**
     * Response validation failed: untrusted chain, signature does not match the challenge/digest, insufficient
     * certLevel, … Do NOT trust the response.
     */
    public static final class Validation extends EidException {
        private static final long serialVersionUID = 1L;
        private final String reason;

        Validation(String reason) {
            this(reason, null);
        }

        Validation(String reason, Throwable cause) {
            super("eid: баталгаажуулалт: " + reason, cause);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    /**
     * The device link cannot be built: deviceLinkBase not https, token / lang / secret malformed, or a field the type
     * needs is missing. Restart the session; never guess the link.
     */
    public static final class DeviceLink extends EidException {
        private static final long serialVersionUID = 1L;
        private final String reason;

        DeviceLink(String reason) {
            super("eid: BuildDeviceLink: " + reason);
            this.reason = reason;
        }

        public String reason() {
            return reason;
        }
    }

    // ── path masking (Go errors.go maskPath) ──

    private static final java.util.regex.Pattern IDENTIFIER_IN_PATH =
        java.util.regex.Pattern.compile("/(etsi|document|linked|requests|seal(?:/certificate|/grants)?)/[^/?#\\s]+");

    /** The path for errors/logs: identifier segments → "…", query and fragment dropped (Go {@code maskPath}). */
    public static String maskPath(String p) {
        int q = -1;
        for (int i = 0; i < p.length(); i++) {
            char c = p.charAt(i);
            if (c == '?' || c == '#') {
                q = i;
                break;
            }
        }
        if (q >= 0) p = p.substring(0, q);
        return IDENTIFIER_IN_PATH.matcher(p).replaceAll("/$1/…");
    }
}
