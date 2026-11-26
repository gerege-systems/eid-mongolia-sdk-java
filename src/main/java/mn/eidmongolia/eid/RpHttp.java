package mn.eidmongolia.eid;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The RP-API HTTP layer (Go {@code client.go} {@code httpDoer}, TS {@code http.ts}): Bearer secret, Accept-Language,
 * per-call deadline, 4 MiB JSON cap, HTTP status → typed {@link EidException}. Thread-safe.
 */
final class RpHttp {
    /** JSON response cap — larger → {@link EidException.ResponseTooLarge} (never truncated and parsed). */
    static final long MAX_JSON_BODY = 4L << 20;
    /** Error bodies are kept up to 64 KiB ({@link EidException.Http#body()}). */
    static final int MAX_ERROR_BODY = 64 << 10;

    final String base;
    private final String secret;
    final Duration timeout;
    private final EidTransport transport;
    final String lang;

    RpHttp(String base, String secret, Duration timeout, EidTransport transport, String lang) {
        this.base = base;
        this.secret = secret;
        this.timeout = timeout;
        this.transport = transport;
        this.lang = lang;
    }

    /** A decoded response: the HTTP status (200 / 201 …) and the JSON value (an empty object for an empty body). */
    record Result(int status, Object json) {
        Json.Obj obj(String op) {
            if (json instanceof Json.Obj) return (Json.Obj) json;
            throw new EidException("eid: " + op + ": хариу JSON объект биш");
        }
    }

    Result postJson(String path, Object body, Duration t) {
        return exchange("POST", path, EidCrypto.utf8(Json.stringify(body)), "application/json", t);
    }

    Result getJson(String path, Duration t) {
        return exchange("GET", path, null, null, t);
    }

    Result exchange(String method, String path, byte[] body, String contentType, Duration t) {
        String op = method + " " + EidException.maskPath(path);
        Duration deadline = t == null || t.isZero() || t.isNegative() ? timeout : t;
        URI uri;
        try {
            uri = URI.create(base + path);
        } catch (IllegalArgumentException e) {
            throw new EidException("eid: request " + op + ": буруу URL");
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Authorization", "Bearer " + secret);
        if (contentType != null) headers.put("Content-Type", contentType);
        if (!lang.isEmpty()) headers.put("Accept-Language", lang);

        EidHttpResponse res;
        try {
            res = transport.send(new EidHttpRequest(method, uri, headers, body, deadline, MAX_JSON_BODY));
        } catch (HttpTimeoutException | SocketTimeoutException e) {
            throw new EidException.Network(op, true, false, e);
        } catch (InterruptedIOException e) {
            Thread.currentThread().interrupt();
            throw new EidException.Network(op, false, true, e);
        } catch (IOException e) {
            throw new EidException.Network(op, false, false, scrub(e, base + path, path, op));
        }
        if (res == null) throw new EidException.Network(op, false, false, new IOException("transport returned no response"));

        if (res.status() >= 300) throw httpError(res, Instant.now());

        String cl = res.header("Content-Length");
        if (cl != null) {
            try {
                if (Long.parseLong(cl.trim()) > MAX_JSON_BODY) throw new EidException.ResponseTooLarge(op, MAX_JSON_BODY);
            } catch (NumberFormatException ignored) {
                // a malformed Content-Length is judged by the body read
            }
        }
        byte[] raw = res.body();
        if (raw.length > MAX_JSON_BODY) throw new EidException.ResponseTooLarge(op, MAX_JSON_BODY);
        if (new String(raw, StandardCharsets.UTF_8).isBlank()) return new Result(res.status(), new Json.Obj());
        try {
            return new Result(res.status(), Json.parse(raw));
        } catch (IllegalArgumentException e) {
            throw new EidException("eid: " + op + ": хариу задарсангүй: " + e.getMessage(), e);
        }
    }

    /** A non-2xx response → {@link EidException.Authentication} / {@link EidException.Forbidden} / {@link EidException.Api} (typed by code). */
    static EidException httpError(EidHttpResponse res, Instant now) {
        byte[] b = res.body();
        String raw = new String(b.length > MAX_ERROR_BODY ? Arrays.copyOf(b, MAX_ERROR_BODY) : b, StandardCharsets.UTF_8);
        String msg = "";
        String code = "";
        String service = "";
        try {
            Object v = Json.parse(raw);
            if (v instanceof Json.Obj) {
                Json.Obj o = (Json.Obj) v;
                msg = o.optString("error");
                code = o.optString("code");
                service = o.optString("service");
            }
        } catch (IllegalArgumentException ignored) {
            // not CA JSON (proxy / nginx): no message, no code
        }
        Duration retry = parseRetryAfter(res.header("Retry-After"), now);
        Map<String, List<String>> h = res.headers();
        int s = res.status();
        switch (s) {
            case 401:
                return new EidException.Authentication(code, msg, raw, h);
            case 403:
                return new EidException.Forbidden(code, msg, raw, retry, h);
            default:
                break;
        }
        switch (code) {
            case EidErrorCodes.NO_SIGNING_CERTIFICATE: return new EidException.NoSigningCertificate(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.CERT_CHOICE_INVALID: return new EidException.CertChoiceInvalid(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.REQUEST_INVALID: return new EidException.RequestInvalid(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.QR_TOKEN_INVALID: return new EidException.QrTokenInvalid(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.ORG_NOT_ACTIVE: return new EidException.OrgNotActive(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_NOT_ISSUED: return new EidException.SealNotIssued(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_CERT_REVOKED: return new EidException.SealCertRevoked(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_KEY_UNAVAILABLE: return new EidException.SealKeyUnavailable(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_CERT_EXPIRED: return new EidException.SealCertExpired(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_CERT_NOT_YET_VALID: return new EidException.SealCertNotYetValid(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_APPROVER_UNAVAILABLE: return new EidException.SealApproverUnavailable(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_REQUEST_NOT_FOUND: return new EidException.SealRequestNotFound(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_SERVICE_DISABLED: return new EidException.SealServiceDisabled(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.AUTH_SESSION_WRONG_FLOW: return new EidException.AuthSessionWrongFlow(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.AUTH_SESSION_NOT_COMPLETED: return new EidException.AuthSessionNotCompleted(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.AUTH_SESSION_TOO_OLD: return new EidException.AuthSessionTooOld(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.AUTH_SESSION_ALREADY_USED: return new EidException.AuthSessionAlreadyUsed(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.AUTH_SESSION_NOT_FOUND: return new EidException.AuthSessionNotFound(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_GRANT_ALREADY_APPROVED: return new EidException.SealGrantAlreadyApproved(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.SEAL_GRANT_NOT_FOUND: return new EidException.SealGrantNotFound(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.RP_NOT_ACTIVE: return new EidException.RpNotActive(s, code, msg, raw, service, retry, h);
            case EidErrorCodes.RP_PERMISSIONS_FULL: return new EidException.RpPermissionsFull(s, code, msg, raw, service, retry, h);
            default: return new EidException.Api(s, code, msg, raw, service, retry, h);
        }
    }

    /**
     * RFC 9110 §10.2.3 (Go {@code parseRetryAfter}): delay-seconds (1…86400) or an IMF-fixdate after {@code now};
     * anything else → {@link Duration#ZERO}.
     */
    static Duration parseRetryAfter(String v, Instant now) {
        v = v == null ? "" : v.trim();
        if (v.isEmpty()) return Duration.ZERO;
        try {
            long n = Long.parseLong(v);
            return n <= 0 || n > 86_400 ? Duration.ZERO : Duration.ofSeconds(n);
        } catch (NumberFormatException ignored) {
            // not delay-seconds
        }
        try {
            Instant t = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            return t.isAfter(now) ? Duration.between(now, t) : Duration.ZERO;
        } catch (DateTimeParseException ignored) {
            return Duration.ZERO;
        }
    }

    /**
     * A transport exception whose message names the full URL (it carries the citizen's identifier) is replaced by one
     * with the masked op (TS {@code http.ts}, Go {@code unwrapURL}).
     */
    private static IOException scrub(IOException e, String url, String path, String op) {
        String m = e.getMessage();
        if (m == null || (!m.contains(url) && !m.contains(path))) return e;
        IOException x = new IOException(e.getClass().getSimpleName() + ": " + m.replace(url, op).replace(path, EidException.maskPath(path)));
        x.setStackTrace(e.getStackTrace());
        return x;
    }
}
