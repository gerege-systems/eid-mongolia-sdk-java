package mn.eidmongolia.eid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** The HTTP layer with a fake {@link EidTransport}: headers, status → typed error mapping, limits, network errors. */
public class HttpErrorTest {
    static final Credentials CREDS = new Credentials("rp-uuid", "Гэрээний систем", "rp_sk_secret");

    /** A transport that records requests and answers from a fixed response (or throws). */
    static final class Fake implements EidTransport {
        final List<EidHttpRequest> seen = new ArrayList<>();
        EidHttpResponse response;
        IOException error;

        Fake respond(int status, String body, String... headers) {
            Map<String, List<String>> h = new java.util.LinkedHashMap<>();
            for (int i = 0; i + 1 < headers.length; i += 2) h.put(headers[i], List.of(headers[i + 1]));
            response = new EidHttpResponse(status, h, body.getBytes(StandardCharsets.UTF_8));
            return this;
        }

        @Override
        public EidHttpResponse send(EidHttpRequest request) throws IOException {
            seen.add(request);
            if (error != null) throw error;
            return response;
        }
    }

    static RpHttp http(Fake f, String lang) {
        return EidClient.builder(CREDS).language(lang).transport(f).build().http();
    }

    static EidException call(Fake f) {
        try {
            http(f, "").getJson(Routes.SESSION.expand("sid-1"), null);
        } catch (EidException e) {
            return e;
        }
        throw new AssertionError("алдаа хүлээв");
    }

    @Test
    public void requestHeadersAndBody() {
        Fake f = new Fake().respond(200, "{\"sessionID\":\"s\"}");
        RpHttp h = http(f, "en");
        RpHttp.Result r = h.postJson(Routes.AUTH_NOTIFICATION_ETSI.expand("PNOMN-АА00000000"), Map.of("relyingPartyName", "Банк"), null);
        assertEquals(200, r.status());
        assertEquals("s", r.obj("x").optString("sessionID"));
        EidHttpRequest q = f.seen.get(0);
        assertEquals("POST", q.method());
        assertEquals("https://rp.eidmongolia.mn/authentication/notification/etsi/PNOMN-%D0%90%D0%9000000000", q.uri().toString());
        assertEquals("Bearer rp_sk_secret", q.headers().get("Authorization"));
        assertEquals("application/json", q.headers().get("Content-Type"));
        assertEquals("en", q.headers().get("Accept-Language"));
        assertEquals(Duration.ofSeconds(15), q.timeout());
        assertEquals(4L << 20, q.maxResponseBytes());
        assertArrayEquals("{\"relyingPartyName\":\"Банк\"}".getBytes(StandardCharsets.UTF_8), q.body());
        assertFalse("secret логт", q.toString().contains("rp_sk_secret"));
        assertFalse("PNOMN логт", q.toString().contains("PNOMN"));

        Fake g = new Fake().respond(200, "  ");
        RpHttp.Result empty = http(g, "").getJson("/session/x", Duration.ofSeconds(40));
        assertTrue(empty.json() instanceof Json.Obj);
        assertNull(g.seen.get(0).body());
        assertNull(g.seen.get(0).headers().get("Content-Type"));
        assertNull(g.seen.get(0).headers().get("Accept-Language"));
        assertEquals(Duration.ofSeconds(40), g.seen.get(0).timeout());
    }

    @Test
    public void authentication401() {
        EidException e = call(new Fake().respond(401, "{\"error\":\"bad secret\",\"code\":\"RP_SECRET_INVALID\"}"));
        assertTrue(e instanceof EidException.Authentication);
        assertEquals("RP_SECRET_INVALID", e.code());
        assertEquals("bad secret", ((EidException.Authentication) e).serverMessage());
        assertEquals(401, e.status());
        e = call(new Fake().respond(401, "<html>proxy</html>"));
        assertTrue(e instanceof EidException.Authentication);
        assertEquals("", e.code());
        assertEquals("", ((EidException.Http) e).serverMessage());
        assertEquals("<html>proxy</html>", ((EidException.Http) e).body());
        assertFalse(e.retryable());
    }

    @Test
    public void forbidden403() {
        EidException e = call(new Fake().respond(403, "{\"error\":\"denied\",\"code\":\"REPRESENTATION_DENIED\"}", "Retry-After", "7"));
        assertTrue(e instanceof EidException.Forbidden);
        assertEquals(EidErrorCodes.REPRESENTATION_DENIED, e.code());
        assertEquals(Duration.ofSeconds(7), e.retryAfter());
        assertEquals("eid: RP-API 403 REPRESENTATION_DENIED: denied", e.getMessage());
        e = call(new Fake().respond(403, ""));
        assertEquals("eid: IP allowlist эсвэл mTLS зөвшөөрөөгүй (403)", e.getMessage());
    }

    @Test
    public void typedApiErrors() {
        String[][] cases = {
            {"409", "NO_SIGNING_CERTIFICATE", "NoSigningCertificate"},
            {"409", "CERT_CHOICE_INVALID", "CertChoiceInvalid"},
            {"400", "REQUEST_INVALID", "RequestInvalid"},
            {"404", "QR_TOKEN_INVALID", "QrTokenInvalid"},
            {"409", "ORG_NOT_ACTIVE", "OrgNotActive"},
            {"409", "SEAL_NOT_ISSUED", "SealNotIssued"},
            {"409", "SEAL_CERT_REVOKED", "SealCertRevoked"},
            {"409", "SEAL_KEY_UNAVAILABLE", "SealKeyUnavailable"},
            {"409", "SEAL_CERT_EXPIRED", "SealCertExpired"},
            {"409", "SEAL_CERT_NOT_YET_VALID", "SealCertNotYetValid"},
            {"409", "SEAL_APPROVER_UNAVAILABLE", "SealApproverUnavailable"},
            {"404", "SEAL_REQUEST_NOT_FOUND", "SealRequestNotFound"},
            {"503", "SEAL_SERVICE_DISABLED", "SealServiceDisabled"},
            {"409", "AUTH_SESSION_WRONG_FLOW", "AuthSessionWrongFlow"},
            {"409", "AUTH_SESSION_NOT_COMPLETED", "AuthSessionNotCompleted"},
            {"409", "AUTH_SESSION_TOO_OLD", "AuthSessionTooOld"},
            {"409", "AUTH_SESSION_ALREADY_USED", "AuthSessionAlreadyUsed"},
            {"404", "AUTH_SESSION_NOT_FOUND", "AuthSessionNotFound"},
            {"409", "SEAL_GRANT_ALREADY_APPROVED", "SealGrantAlreadyApproved"},
            {"404", "SEAL_GRANT_NOT_FOUND", "SealGrantNotFound"},
            {"409", "RP_NOT_ACTIVE", "RpNotActive"},
            {"409", "RP_PERMISSIONS_FULL", "RpPermissionsFull"},
            {"409", "DOC_ID_CONFLICT", "Api"},
            {"500", "", "Api"},
        };
        for (String[] c : cases) {
            int status = Integer.parseInt(c[0]);
            String body = c[1].isEmpty() ? "oops" : "{\"error\":\"x\",\"code\":\"" + c[1] + "\"}";
            EidException e = call(new Fake().respond(status, body));
            assertEquals(c[1], c[2], e.getClass().getSimpleName());
            assertTrue(e instanceof EidException.Api);
            assertEquals(status, e.status());
            assertEquals(c[1], e.code());
            assertEquals("eid: RP-API " + status + ": " + body, e.getMessage());
        }
    }

    @Test
    public void retryable() {
        EidException e = call(new Fake().respond(429, "{\"error\":\"x\",\"code\":\"RATE_LIMITED\"}", "Retry-After", "3"));
        assertTrue(e.retryable());
        assertEquals(Duration.ofSeconds(3), e.retryAfter());
        e = call(new Fake().respond(503, "{\"error\":\"x\",\"code\":\"STATE_UNAVAILABLE\"}"));
        assertTrue("code-оор", e.retryable());
        assertEquals(Duration.ZERO, e.retryAfter());
        e = call(new Fake().respond(503, "Service Unavailable", "retry-after", "5"));
        assertTrue("503 + Retry-After", e.retryable());
        e = call(new Fake().respond(503, "Service Unavailable"));
        assertFalse("503 Retry-After-гүй", e.retryable());
        e = call(new Fake().respond(500, "x", "Retry-After", "5"));
        assertFalse("500", e.retryable());
        e = call(new Fake().respond(503, "{\"error\":\"off\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"sealing\"}", "Retry-After", "5"));
        assertTrue(e instanceof EidException.SealServiceDisabled);
        assertFalse("SEAL_SERVICE_DISABLED хэзээ ч үгүй", e.retryable());
        assertEquals(EidErrorCodes.SEAL_SERVICE_SEALING, ((EidException.Api) e).service());
        assertEquals("5", ((EidException.Http) e).header("RETRY-AFTER"));
    }

    @Test
    public void parseRetryAfter() {
        Instant now = Instant.parse("2026-11-26T08:00:00Z");
        assertEquals(Duration.ofSeconds(120), RpHttp.parseRetryAfter(" 120 ", now));
        assertEquals(Duration.ofSeconds(5), RpHttp.parseRetryAfter("+5", now));
        assertEquals(Duration.ofSeconds(86_400), RpHttp.parseRetryAfter("86400", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("86401", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("0", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("-5", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("99999999999999999999", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter(null, now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("soon", now));
        assertEquals(Duration.ofSeconds(90), RpHttp.parseRetryAfter("Thu, 26 Nov 2026 08:01:30 GMT", now));
        assertEquals(Duration.ZERO, RpHttp.parseRetryAfter("Thu, 26 Nov 2026 07:59:00 GMT", now));
    }

    @Test
    public void errorBodyTruncatedTo64KiB() {
        char[] big = new char[100_000];
        Arrays.fill(big, 'x');
        EidException e = call(new Fake().respond(502, new String(big)));
        assertEquals(64 << 10, ((EidException.Http) e).body().length());
    }

    @Test
    public void responseTooLarge() {
        byte[] body = new byte[(4 << 20) + 1];
        Arrays.fill(body, (byte) ' ');
        Fake f = new Fake();
        f.response = new EidHttpResponse(200, Map.of(), body);
        EidException e = call(f);
        assertTrue(e instanceof EidException.ResponseTooLarge);
        assertEquals("GET /session/sid-1", ((EidException.ResponseTooLarge) e).op());
        e = call(new Fake().respond(200, "{}", "Content-Length", String.valueOf((4 << 20) + 1)));
        assertTrue("Content-Length", e instanceof EidException.ResponseTooLarge);
    }

    @Test
    public void invalidJson() {
        EidException e = call(new Fake().respond(200, "{not json"));
        assertSame(EidException.class, e.getClass());
        assertTrue(e.getMessage().startsWith("eid: GET /session/sid-1: хариу задарсангүй"));
    }

    @Test
    public void networkErrorsMaskIdentifiers() {
        Fake f = new Fake();
        f.error = new ConnectException("connect to https://rp.eidmongolia.mn/authentication/notification/etsi/PNOMN-AA00000000 failed");
        try {
            http(f, "").postJson(Routes.AUTH_NOTIFICATION_ETSI.expand("PNOMN-AA00000000"), Map.of(), null);
            fail();
        } catch (EidException.Network e) {
            assertEquals("POST /authentication/notification/etsi/…", e.op());
            assertFalse(e.timeout());
            assertFalse(e.cancelled());
            assertFalse(e.getMessage(), e.getMessage().contains("PNOMN"));
            assertFalse(e.getCause().getMessage(), e.getCause().getMessage().contains("PNOMN"));
        }
        f.error = new HttpTimeoutException("request timed out");
        try {
            http(f, "").getJson("/session/x", null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.timeout());
            assertEquals("eid: хүсэлт хугацаа хэтэрлээ: GET /session/x", e.getMessage());
        }
        f.error = new java.net.SocketTimeoutException("read timed out");
        try {
            http(f, "").getJson("/session/x", null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.timeout());
        }
    }

    @Test
    public void interruptCancels() {
        Fake f = new Fake();
        f.error = new InterruptedIOException("interrupted");
        try {
            http(f, "").getJson("/session/x", null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.cancelled());
            assertFalse(e.timeout());
            assertTrue("interrupt flag хэвээр", Thread.interrupted()); // clears it for the next test
        }
    }

    @Test
    public void sessionTtlFromDiscovery() {
        Fake f = new Fake().respond(200, "{\"rp_api_base\":\"https://rp.eidmongolia.mn\",\"sessionTtl\":{\"auth\":300,\"sign\":900}}");
        EidClient c = EidClient.builder(CREDS).transport(f).build();
        assertEquals(new SessionTtl(Duration.ofSeconds(300), Duration.ofSeconds(900)), c.auth().sessionTtl());
        assertEquals("GET", f.seen.get(0).method());
        assertEquals("https://rp.eidmongolia.mn/.well-known/eid", f.seen.get(0).uri().toString());
        f.respond(200, "{\"sessionTtl\":{\"auth\":0}}");
        assertEquals(new SessionTtl(Duration.ZERO, Duration.ZERO), c.auth().sessionTtl());
        f.respond(200, "{}");
        assertEquals(new SessionTtl(Duration.ZERO, Duration.ZERO), c.auth().sessionTtl());
    }

    @Test
    public void routesAndMaskPath() {
        assertEquals(33, Routes.ALL.size());
        assertEquals("/session/a%2Fb%3Fc%23d%20e", Routes.SESSION.expand("a/b?c#d e"));
        assertEquals("/session/$&+:=@-._~", Routes.SESSION.expand("$&+:=@-._~"));
        assertEquals("/seal/certificate/NTRMN-1/requests/r1", Routes.SEAL_CERTIFICATE_REQUEST_STATUS.expand("NTRMN-1", "r1"));
        try {
            Routes.SESSION.expand();
            fail("дутуу");
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            Routes.SESSION.expand("a", "b");
            fail("илүү");
        } catch (IllegalArgumentException expected) {
            // ok
        }
        assertEquals("/authentication/notification/etsi/…", EidException.maskPath("/authentication/notification/etsi/PNOMN-AA00000000?x=1"));
        assertEquals("/signature/notification/document/…", EidException.maskPath("/signature/notification/document/PNOMN-AA-1#f"));
        assertEquals("/signature/notification/linked/…", EidException.maskPath("/signature/notification/linked/D1"));
        assertEquals("/seal/certificate/…/requests/…", EidException.maskPath("/seal/certificate/NTRMN-1/requests/r1"));
        assertEquals("/seal/grants/…", EidException.maskPath("/seal/grants/g1"));
        assertEquals("/seal/…", EidException.maskPath("/seal/NTRMN-1"));
        assertEquals("/session/sid", EidException.maskPath("/session/sid"));
    }
}
