package mn.eidmongolia.eid;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Session polling ({@link EidClient#session()}, Go {@code SessionService}, TS {@code SessionApi}). The RP-API long-polls
 * up to serverPoll (or until the citizen answers), so a few calls give the result.
 *
 * <p>All calls are blocking; {@link Thread#interrupt()} cancels a call in flight ({@link EidException.Network#cancelled()}).
 */
public final class SessionService {
    /** One server long-poll's maximum. */
    public static final Duration DEFAULT_SERVER_POLL = Duration.ofSeconds(30);
    /**
     * The total wait's fallback when neither maxWait, expiresAt nor the discovery sessionTtl is known (= the CA's default
     * signature session lifetime, 600 s).
     */
    public static final Duration DEFAULT_MAX_WAIT = Duration.ofSeconds(600);
    /**
     * Extra wait after expiresAt / the discovery sessionTtl: the CA turns an expired session into COMPLETE/TIMEOUT on the
     * next poll, so the last poll runs after the expiry and absorbs small clock skew.
     */
    public static final Duration WAIT_GRACE = Duration.ofSeconds(15);

    private final RpHttp http;
    private final Clock clock;

    SessionService(RpHttp http, Clock clock) {
        this.http = http;
        this.clock = clock;
    }

    /**
     * One long-poll (GET /session/{id}?timeoutMs=…); serverPoll null / ≤ 0 = {@link #DEFAULT_SERVER_POLL}. The HTTP
     * timeout is serverPoll + 10 s.
     */
    public SessionResult poll(String sessionId, Duration serverPoll) {
        Duration p = serverPoll == null || serverPoll.isZero() || serverPoll.isNegative() ? DEFAULT_SERVER_POLL : serverPoll;
        String path = Routes.SESSION.expand(sessionId) + "?timeoutMs=" + p.toMillis();
        RpHttp.Result r = http.getJson(path, p.plusSeconds(10));
        if (r.raw().length == 0) return parse(new Json.Obj(), "");
        return parse(r.obj("GET /session/…"), new String(r.raw(), StandardCharsets.UTF_8));
    }

    /**
     * Polls until COMPLETE. By default it waits for the session's lifetime ({@link WaitOptions.Builder#maxWait}) — the CA
     * turns an expired session into COMPLETE/TIMEOUT, so normally that result arrives. When the deadline passes before
     * COMPLETE the last (RUNNING) result is returned WITHOUT an error — treat endResult "" like TIMEOUT, or call
     * {@link #requireOk}. A non-OK COMPLETE result is returned as is (the validator / {@link #requireOk} turn it into
     * {@link EidException.SessionFailed}).
     *
     * @param options null = defaults
     */
    public SessionResult waitForResult(String sessionId, WaitOptions options) {
        WaitOptions o = options == null ? WaitOptions.DEFAULTS : options;
        Duration poll = o.serverPoll != null && !o.serverPoll.isZero() && !o.serverPoll.isNegative() ? o.serverPoll : DEFAULT_SERVER_POLL;
        Instant deadline = waitDeadline(o);
        Json.Obj running = new Json.Obj();
        running.keys.add("state");
        running.values.add(SessionResult.STATE_RUNNING);
        SessionResult last = parse(running, "");
        while (true) {
            Duration remaining = Duration.between(clock.instant(), deadline);
            if (remaining.isZero() || remaining.isNegative()) return last;
            Duration p = poll.compareTo(remaining) < 0 ? poll : remaining;
            if (p.compareTo(Duration.ofSeconds(1)) < 0) p = Duration.ofSeconds(1);
            SessionResult r = poll(sessionId, p);
            last = r;
            if (SessionResult.STATE_COMPLETE.equals(r.state())) return r;
        }
    }

    /** waitForResult's deadline: maxWait &gt; expiresAt &gt; discovery sessionTtl &gt; {@link #DEFAULT_MAX_WAIT} (Go {@code waitDeadline}). */
    Instant waitDeadline(WaitOptions o) {
        Instant now = clock.instant();
        if (o.maxWait != null && !o.maxWait.isZero() && !o.maxWait.isNegative()) return now.plus(o.maxWait);
        if (o.expiresAt != null) {
            // Already past: still one poll — it fetches the CA's COMPLETE/TIMEOUT.
            Instant d = o.expiresAt.plus(WAIT_GRACE);
            Instant min = now.plusSeconds(1);
            return d.isAfter(min) ? d : min;
        }
        // The session kind (auth / sign) is unknown here — the longer is safe: the CA itself times an expired session
        // out. Discovery failing → the fallback (not an error), unless the call was cancelled by an interrupt.
        try {
            SessionTtl t = AuthService.fetchSessionTtl(http, null);
            Duration d = t.auth().compareTo(t.sign()) > 0 ? t.auth() : t.sign();
            if (!d.isZero() && !d.isNegative()) return now.plus(d).plus(WAIT_GRACE);
        } catch (EidException.Network e) {
            if (e.cancelled()) throw e;
        } catch (EidException e) {
            // the fallback
        }
        return now.plus(DEFAULT_MAX_WAIT);
    }

    /**
     * Requires a COMPLETE / OK result (Go validator.go {@code sessionDone}): not COMPLETE →
     * {@link EidException.Validation}; endResult ≠ OK → {@link EidException.SessionFailed} (endResult; "" → UNKNOWN).
     *
     * @return {@code r}
     */
    public static SessionResult requireOk(SessionResult r) {
        if (r == null) throw new EidException.Validation(ValidationReasons.SESSION_NOT_COMPLETE, "хариу алга");
        if (!SessionResult.STATE_COMPLETE.equals(r.state())) {
            throw new EidException.Validation(ValidationReasons.SESSION_NOT_COMPLETE, "session дуусаагүй (state=" + r.state() + ")");
        }
        if (!SessionResult.END_RESULT_OK.equals(r.endResult())) {
            throw new EidException.SessionFailed(r.endResult() == null || r.endResult().isEmpty() ? "UNKNOWN" : r.endResult());
        }
        return r;
    }

    /**
     * Parses an RP-API session JSON (to re-check a stored response, tests; Go {@code ParseSessionResult}, TS
     * {@code parseSessionResult}).
     *
     * @throws EidException when the text is not a JSON object
     */
    public static SessionResult parseSessionResult(String json) {
        Object v;
        try {
            v = Json.parse(json);
        } catch (IllegalArgumentException e) {
            throw new EidException("eid: session JSON: " + e.getMessage(), e);
        }
        if (!(v instanceof Json.Obj)) throw new EidException("eid: session JSON: объект биш");
        return parse((Json.Obj) v, json);
    }

    /** Go session.go {@code rawSession.result}: empty blocks → null. */
    static SessionResult parse(Json.Obj r, String raw) {
        Json.Obj result = obj(r, "result");
        Json.Obj sig = obj(r, "signature");
        Json.Obj cert = obj(r, "cert");
        String proto = r.optString("signatureProtocol");
        if (proto.isEmpty()) proto = sig.optString("signatureProtocol");
        return new SessionResult(
            r.optString("state"),
            result.optString("endResult"),
            result.optString("documentNumber"),
            cert.optString("value"),
            cert.optString("certificateLevel"),
            sig.optString("value"),
            sig.optString("signatureAlgorithm"),
            proto,
            sig.optString("serverRandom"),
            sig.optString("userChallenge"),
            sig.optString("flowType"),
            // "" is a value (signed into ACSP_V2); null = field absent (older CA).
            sig.optStringOrNull("initialCallbackUrl"),
            sigParams(sig.optObj("signatureAlgorithmParameters")),
            r.optString("interactionTypeUsed"),
            org(r.optObj("onBehalfOf")),
            person(r.optObj("person")),
            tokenCert(r.optObj("tokenCertificate")),
            presentation(r.optObj("presentation")),
            raw);
    }

    private static Json.Obj obj(Json.Obj o, String k) {
        Json.Obj v = o.optObj(k);
        return v == null ? new Json.Obj() : v;
    }

    private static SignatureAlgorithmParameters sigParams(Json.Obj p) {
        if (p == null || p.optString("hashAlgorithm").isEmpty()) return null;
        Json.Obj mgf = obj(p, "maskGenAlgorithm");
        Integer salt = null;
        Object s = p.get("saltLength");
        if (s instanceof Json.Num) {
            Long l = ((Json.Num) s).exactLong();
            if (l != null && l >= Integer.MIN_VALUE && l <= Integer.MAX_VALUE) salt = l.intValue();
        }
        return new SignatureAlgorithmParameters(p.optString("hashAlgorithm"), mgf.optString("algorithm"),
            obj(mgf, "parameters").optString("hashAlgorithm"), salt, p.optString("trailerField"));
    }

    private static OrgResult org(Json.Obj o) {
        if (o == null || o.optString("orgEtsi").isEmpty()) return null;
        return new OrgResult(o.optString("orgEtsi"), o.optString("orgName"), o.optString("role"), o.optString("roleLabel"),
            o.optString("rightType"), o.optString("rightTypeLabel"));
    }

    private static Person person(Json.Obj p) {
        if (p == null) return null;
        Person out = new Person(p.optString("firstName"), p.optString("lastName"), p.optString("familyName"),
            p.optString("firstNameEn"), p.optString("lastNameEn"), p.optString("civilId"), p.optString("regNo"),
            p.optString("birthDate"), p.optString("gender"), p.optLong("geID", 0), p.optString("nationality"));
        return out.equals(new Person("", "", "", "", "", "", "", "", "", 0, "")) ? null : out;
    }

    private static TokenCertSessionBlock tokenCert(Json.Obj t) {
        if (t == null || t.optString("status").isEmpty()) return null;
        return new TokenCertSessionBlock(t.optString("status"), t.optString("errorCode"), t.optString("authSerialHex"),
            t.optString("signSerialHex"));
    }

    private static String presentation(Json.Obj p) {
        if (p == null || p.optString("jws").isEmpty()) return null;
        return p.optString("jws");
    }
}
