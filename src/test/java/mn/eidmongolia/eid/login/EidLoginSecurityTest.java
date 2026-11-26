package mn.eidmongolia.eid.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.Consumer;
import java.util.function.Predicate;
import mn.eidmongolia.eid.AcspContext;
import mn.eidmongolia.eid.Credentials;
import mn.eidmongolia.eid.EidClient;
import mn.eidmongolia.eid.EidHttpRequest;
import mn.eidmongolia.eid.EidHttpResponse;
import mn.eidmongolia.eid.EidTransport;
import mn.eidmongolia.eid.FlowType;
import mn.eidmongolia.eid.HashAlgorithm;
import mn.eidmongolia.eid.RevocationChecker;
import mn.eidmongolia.eid.RevocationMode;
import mn.eidmongolia.eid.RevocationOutcome;
import mn.eidmongolia.eid.RevocationStatus;
import mn.eidmongolia.eid.SignatureAlgorithm;
import mn.eidmongolia.eid.TestAccess;
import mn.eidmongolia.eid.TrustConfig;
import org.junit.Test;

/**
 * The login handler's security cases the corpus leaves out (ports of Go eidlogin/security_test.go and eidlogin_test.go;
 * TS login.test.ts): the push floor on a fake clock, the OK path with a REAL ACSP_V2 signature from the conformance PKI
 * (rp-validate vectors), revocation outcomes, store eviction / cap, session fixation (a fresh RP session cookie next to
 * the cleared login cookie), cross-site and method refusals, cookie binding, replay of a completed sign-in, limiter
 * fail-closed, client-IP derivation and the Web2App return hint.
 */
public class EidLoginSecurityTest {
    static final String SID = "0b5e6a4c-1d2e-4f3a-8b9c-0d1e2f3a4b5c";
    static final String RP_UUID = "00000000-0000-4000-8000-000000000001";
    static final String CALLBACK = "https://rp.conformance.test/auth/eid/callback";
    static final Instant NOW = Instant.parse("2026-10-14T04:00:00Z");

    static final class FakeClock extends Clock {
        volatile Instant now;

        FakeClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    /** A programmable fake RP-API: push mode (ok | json400 | 500 | proxy400 | 401), session JSON, 404, discovery. */
    static final class Fake implements EidTransport {
        volatile String push = "ok";
        volatile String session = "{\"state\":\"RUNNING\"}";
        volatile int sessionStatus = 200;
        volatile String discovery = "{\"version\":\"v3\"}";
        /** When set, a /session/ call waits on it (a long-poll in progress). */
        volatile java.util.concurrent.CountDownLatch sessionGate;
        final List<String> calls = Collections.synchronizedList(new ArrayList<>());

        static EidHttpResponse json(int s, String body) {
            return new EidHttpResponse(s, Map.of("Content-Type", List.of("application/json")), body.getBytes(StandardCharsets.UTF_8));
        }

        @Override
        public EidHttpResponse send(EidHttpRequest r) {
            String p = r.uri().getRawPath();
            calls.add(r.method() + " " + p);
            if (p.equals("/.well-known/eid")) return json(200, discovery);
            if (p.equals("/authentication/device-link/anonymous")) {
                return json(200, "{\"sessionID\":\"" + SID + "\",\"sessionToken\":\"tok_Conformance-0001\",\"sessionSecret\":"
                    + "\"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTAwMQ==\",\"deviceLinkBase\":\"https://eid.conformance.test/dl\",\"vc\":\"12345\"}");
            }
            if (p.startsWith("/authentication/notification/etsi/")) {
                switch (push) {
                    case "json400":
                        return json(400, "{\"error\":\"хэрэглэгч олдсонгүй\"}");
                    case "500":
                        return json(500, "{\"error\":\"x\"}");
                    case "proxy400":
                        return new EidHttpResponse(400, Map.of("Content-Type", List.of("text/html")), "<html>400</html>".getBytes(StandardCharsets.UTF_8));
                    case "401":
                        return json(401, "{\"error\":\"unauthorized\"}");
                    default:
                        return json(200, "{\"sessionID\":\"" + SID + "\",\"vc\":{\"type\":\"alphaNumeric4\",\"value\":\"54321\"}}");
                }
            }
            if (p.startsWith("/session/")) {
                java.util.concurrent.CountDownLatch g = sessionGate;
                if (g != null) {
                    try {
                        g.await(10, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                    }
                }
                return json(sessionStatus, session);
            }
            return json(404, "{\"error\":\"not found\"}");
        }
    }

    /** One test environment (Go eidlogin_test.go {@code setup}). */
    static final class Env {
        final Fake fake = new Fake();
        final FakeClock clock = new FakeClock(NOW);
        final List<Duration> sleeps = Collections.synchronizedList(new ArrayList<>());
        final List<EidLoginEvent> events = Collections.synchronizedList(new ArrayList<>());
        final List<EidLoginIdentity> ids = Collections.synchronizedList(new ArrayList<>());
        EidLoginStore store;
        AcspContext acspOverride;
        EidLogin login;

        Env(Consumer<EidLogin.Builder> mod, TrustConfig trust) {
            EidClient client = TestAccess.clock(EidClient.builder(new Credentials(RP_UUID, "Тест банк", "rp_sk_test"))
                .baseUrl("https://rp-api.conformance.test").transport(fake).trust(trust), clock).build();
            EidLoginStore mem = EidLoginStore.memory(EidLoginStore.MEMORY_MAX, clock);
            // The vectors' ACSP context replaces the random one the handler stored (the RP-side state of the signed session).
            store = new EidLoginStore() {
                @Override
                public EidLoginTx get(String id) {
                    return mem.get(id);
                }

                @Override
                public void set(EidLoginTx tx, Duration ttl) {
                    AcspContext a = acspOverride;
                    mem.set(a == null || tx.decoy() ? tx : new EidLoginTx(tx.sessionId(), tx.bindingHash(), tx.mode(), tx.expiresAt(), tx.vc(), a,
                        tx.link(), tx.decoy()), ttl);
                }

                @Override
                public boolean delete(String id) {
                    return mem.delete(id);
                }
            };
            EidLogin.Builder b = EidLogin.builder(client).callbackUrl(CALLBACK).failureRedirect("/login").store(store).clock(clock)
                .sleeper(d -> {
                    sleeps.add(d);
                    clock.advance(d);
                })
                .onEvent(events::add)
                .disableRevocation(true)
                .onSuccess((id, req) -> {
                    ids.add(id);
                    return new EidLoginSuccess("/dashboard", Map.of("user", id.etsi()), Map.of("Set-Cookie", List.of("app_session=fresh; Path=/; HttpOnly; Secure")));
                });
            if (mod != null) mod.accept(b);
            login = b.build();
        }

        EidLoginResponse post(String path, String json, Map<String, String> headers) {
            Map<String, List<String>> h = new LinkedHashMap<>();
            h.put("Content-Type", List.of("application/json"));
            if (headers != null) headers.forEach((k, v) -> h.put(k, List.of(v)));
            return login.handle(EidLoginRequest.of("POST", path, h, json, null));
        }

        EidLoginResponse get(String path, String cookie) {
            Map<String, List<String>> h = new LinkedHashMap<>();
            if (cookie != null) h.put("Cookie", List.of(cookie));
            return login.handle(EidLoginRequest.of("GET", path, h, null, null));
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> body(EidLoginResponse r) {
        return (Map<String, Object>) LoginJson.parse(r.body().getBytes(StandardCharsets.UTF_8));
    }

    static String loginCookie(EidLoginResponse r) {
        for (String sc : r.headers().getOrDefault("Set-Cookie", List.of())) {
            if (sc.startsWith("eid_login=")) return sc.substring(0, sc.indexOf(';'));
        }
        throw new AssertionError("no login cookie: " + r.headers());
    }

    // Go TestPushDecoyIndistinguishable (timing + shape on the fake clock)
    @Test
    public void pushFloorAndDecoyOnFakeClock() {
        Env e = new Env(null, null);
        EidLoginResponse real = e.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", null);
        e.fake.push = "json400";
        EidLoginResponse decoy = e.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ87654321\"}", null);
        assertEquals(200, real.status());
        assertEquals(200, decoy.status());
        assertEquals(new TreeSet<>(body(real).keySet()), new TreeSet<>(body(decoy).keySet()));
        assertEquals(body(real).get("expiresIn").toString(), body(decoy).get("expiresIn").toString());
        assertEquals("both take the full floor", List.of(Duration.ofSeconds(1), Duration.ofSeconds(1)), e.sleeps);

        e.sleeps.clear();
        String rc = loginCookie(real);
        String dc = loginCookie(decoy);
        int before = e.fake.calls.size();
        EidLoginResponse rp = e.get("/auth/eid/status", rc);
        EidLoginResponse dp = e.get("/auth/eid/status", dc);
        assertEquals("PENDING", body(rp).get("state"));
        assertEquals("PENDING", body(dp).get("state"));
        assertEquals(new TreeSet<>(body(rp).keySet()), new TreeSet<>(body(dp).keySet()));
        assertEquals(body(decoy).get("vc"), body(dp).get("vc"));
        assertEquals("the decoy holds for the poll, never asks eID", List.of(EidLogin.DEFAULT_POLL), e.sleeps);
        assertEquals("only the real status asked eID", before + 1, e.fake.calls.size());
        // after the lifetime: EXPIRED, like an unanswered real push
        e.clock.advance(Duration.ofMinutes(3));
        assertEquals("EXPIRED", body(e.get("/auth/eid/status", dc)).get("state"));
        assertEquals(2, e.events.size());
        assertEquals(Boolean.FALSE, e.events.get(0).meta().get("decoy"));
        assertEquals(Boolean.TRUE, e.events.get(1).meta().get("decoy"));
        assertNotEquals(e.events.get(0).meta().get("pushKey"), e.events.get(1).meta().get("pushKey"));
        for (EidLoginEvent ev : e.events) assertFalse(ev.meta().toString(), ev.meta().toString().contains("12345678"));

        // Go TestPushOutageNotDecoy: outages are 502 with the floor kept, no event.
        for (String mode : new String[] {"500", "proxy400", "401"}) {
            Env o = new Env(null, null);
            o.fake.push = mode;
            EidLoginResponse r = o.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", null);
            assertEquals(mode, 502, r.status());
            assertEquals("eid_unavailable", body(r).get("error"));
            assertEquals(mode, List.of(Duration.ofSeconds(1)), o.sleeps);
            assertTrue(o.events.isEmpty());
        }
        // Go TestDecoyAndFloorOptOut
        Env off = new Env(b -> b.disableDecoy(true).disablePushFloor(true), null);
        off.fake.push = "json400";
        assertEquals(502, off.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", null).status());
        assertTrue(off.sleeps.isEmpty());
        Env three = new Env(b -> b.pushFloor(Duration.ofSeconds(3)), null);
        three.post("/auth/eid/start", "{\"mode\":\"qr\"}", null);
        three.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", null);
        assertEquals("QR has no floor", List.of(Duration.ofSeconds(3)), three.sleeps);
    }

    // ── the OK path with a real ACSP_V2 signature (conformance rp-validate vectors) ──

    @SuppressWarnings("unchecked")
    static Map<String, Object> rpCase(String name) {
        Map<String, Object> f = (Map<String, Object>) LoginJson.parse(resource("conformance/rp-validate/cases.json"));
        for (Object o : (List<Object>) f.get("cases")) {
            Map<String, Object> c = (Map<String, Object>) o;
            if (name.equals(c.get("name"))) {
                c.put("$trust", ((Map<String, Object>) f.get("trust")).get(c.get("trust")));
                return c;
            }
        }
        throw new AssertionError(name);
    }

    static byte[] resource(String name) {
        try (InputStream in = EidLoginSecurityTest.class.getResourceAsStream("/" + name)) {
            assertNotNull(name, in);
            return in.readAllBytes();
        } catch (IOException x) {
            throw new IllegalStateException(x);
        }
    }

    @SuppressWarnings("unchecked")
    static TrustConfig trust(Map<String, Object> tr) {
        List<String> anchors = new ArrayList<>();
        for (Object p : (List<Object>) tr.get("anchors")) anchors.add(new String(resource("conformance/" + p), StandardCharsets.US_ASCII));
        List<String> inters = new ArrayList<>();
        for (Object p : (List<Object>) tr.get("intermediates")) inters.add(new String(resource("conformance/" + p), StandardCharsets.US_ASCII));
        List<String> skis = new ArrayList<>();
        for (Object s : (List<Object>) tr.get("allowedIssuerSkis")) skis.add((String) s);
        return TrustConfig.builder().trustAnchorsPem(anchors).intermediatesPem(inters).allowedIssuerSkis(skis).build();
    }

    @SuppressWarnings("unchecked")
    static AcspContext acsp(Map<String, Object> a) {
        List<FlowType> flows = new ArrayList<>();
        for (Object f : (List<Object>) a.get("flowTypes")) flows.add(FlowType.fromWire((String) f));
        return new AcspContext((String) a.get("rpChallenge"), (String) a.get("relyingPartyName"), (String) a.get("brokeredRpName"),
            (String) a.get("interactions"), (String) a.get("initialCallbackUrl"), flows,
            SignatureAlgorithm.fromWire((String) a.get("signatureAlgorithm")), HashAlgorithm.fromWire((String) a.get("hashAlgorithm")));
    }

    static Env vectorEnv(String name, Consumer<EidLogin.Builder> mod) {
        Map<String, Object> c = rpCase(name);
        assertEquals(NOW.toString(), c.get("now"));
        @SuppressWarnings("unchecked")
        Env e = new Env(mod, trust((Map<String, Object>) c.get("$trust")));
        e.acspOverride = acsp(EidLoginConformanceTest.obj(c.get("acsp")));
        e.fake.session = LoginJson.stringify(c.get("session"));
        return e;
    }

    // Go eidlogin_test.go TestQRFlow (OK) with the conformance vector auth-pss-sha512-qr; replay of a completed sign-in
    @Test
    public void qrOkWithRealSignatureThenReplay() {
        Env e = vectorEnv("auth-pss-sha512-qr", null);
        String saved = e.fake.session;
        e.fake.session = "{\"state\":\"RUNNING\"}";
        EidLoginResponse s = e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null);
        assertEquals(200, s.status());
        String cookie = loginCookie(s);
        e.fake.session = saved;
        EidLoginResponse r = e.get("/auth/eid/status", cookie);
        Map<String, Object> b = body(r);
        assertEquals(r.body(), "OK", b.get("state"));
        assertEquals("/dashboard", b.get("redirect"));
        assertEquals(Map.of("user", "PNOMN-999999990001"), b.get("data"));
        // fixation: the login cookie is cleared AND the RP's fresh session cookie is set
        List<String> sc = r.headers().get("Set-Cookie");
        assertTrue(sc.toString(), sc.stream().anyMatch(x -> x.startsWith("eid_login=; ") && x.contains("Max-Age=0")));
        assertTrue(sc.toString(), sc.contains("app_session=fresh; Path=/; HttpOnly; Secure"));
        assertEquals(1, e.ids.size());
        EidLoginIdentity id = e.ids.get(0);
        assertEquals(SID, id.sessionId());
        assertEquals("PNOMN-999999990001", id.etsi());
        assertEquals("999999990001", id.civilId());
        assertEquals("TEST", id.givenName());
        assertEquals("TESTOV", id.surname());
        assertEquals("PNOMN-999999990001-MOCK-Q", id.documentNumber());
        assertEquals(FlowType.QR, id.flowType());
        assertEquals(RevocationOutcome.SKIPPED, id.revocation());
        assertNull("no person block in the vector", id.person());
        EidLoginEvent last = e.events.get(e.events.size() - 1);
        assertEquals(EidLoginEvent.Kind.SUCCESS, last.kind());
        assertEquals(Map.of("mode", "qr", "flow", "QR", "revocation", "skipped"), last.meta());
        // Replay: the same cookie after completion — EXPIRED, onSuccess never runs twice.
        assertEquals("EXPIRED", body(e.get("/auth/eid/status", cookie)).get("state"));
        assertEquals(1, e.ids.size());
    }

    // Go TestRevocation, on the real-signature vector
    @Test
    public void revocationOutcomes() {
        Object[][] cases = {
            {"revoked", (RevocationChecker) (c, i) -> RevocationStatus.REVOKED, null, "FAILED", "revoked", null},
            {"checker error", (RevocationChecker) (c, i) -> {
                throw new IllegalStateException("boom");
            }, null, "FAILED", "revocation_unavailable", null},
            {"hard-fail unknown", (RevocationChecker) (c, i) -> RevocationStatus.UNKNOWN, RevocationMode.HARD_FAIL, "FAILED", "revocation_unavailable", null},
            {"soft unknown", (RevocationChecker) (c, i) -> RevocationStatus.UNKNOWN, null, "OK", "", RevocationOutcome.UNCHECKED},
            {"good", (RevocationChecker) (c, i) -> RevocationStatus.GOOD, null, "OK", "", RevocationOutcome.GOOD},
        };
        for (Object[] c : cases) {
            Env e = vectorEnv("auth-pss-sha512-qr", b -> b.disableRevocation(false).revocation((RevocationChecker) c[1])
                .revocationMode((RevocationMode) c[2]));
            String saved = e.fake.session;
            e.fake.session = "{\"state\":\"RUNNING\"}";
            String cookie = loginCookie(e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
            e.fake.session = saved;
            Map<String, Object> b = body(e.get("/auth/eid/status", cookie));
            assertEquals((String) c[0], c[3], b.get("state"));
            EidLoginEvent last = e.events.get(e.events.size() - 1);
            if ("FAILED".equals(c[3])) {
                assertEquals("VALIDATION", b.get("error"));
                assertTrue(e.ids.isEmpty());
                assertEquals(EidLoginEvent.Kind.UNVERIFIED, last.kind());
                assertEquals((String) c[0], c[4], last.meta().get("reason"));
            } else {
                assertEquals(c[5], e.ids.get(0).revocation());
                assertEquals(((RevocationOutcome) c[5]).wireName(), last.meta().get("revocation"));
            }
        }
    }

    // Go TestWeb2AppFlow with the vector auth-web2app-verifier; wrong verifier; replay of the callback
    @Test
    public void web2AppCallbackWithRealSignature() {
        Map<String, Object> vc = rpCase("auth-web2app-verifier");
        String verifier = (String) EidLoginConformanceTest.obj(vc.get("options")).get("userChallengeVerifier");
        for (boolean good : new boolean[] {true, false}) {
            Env e = vectorEnv("auth-web2app-verifier", null);
            String saved = e.fake.session;
            e.fake.session = "{\"state\":\"RUNNING\"}";
            EidLoginResponse s = e.get("/auth/eid/start?mode=web2app", null);
            assertEquals(302, s.status());
            assertTrue(s.header("Location").startsWith("https://eid.conformance.test/dl?"));
            String cookie = loginCookie(s);
            e.fake.session = saved;
            assertEquals("WAIT_CALLBACK", body(e.get("/auth/eid/status", cookie)).get("state"));
            String v = good ? verifier : "d3Jvbmctdmlld2luZy12ZXJpZmllci0wMDAwMDAwMDE";
            EidLoginResponse cb = e.get("/auth/eid/callback?sessionId=" + SID + "&userChallengeVerifier=" + v, cookie);
            assertEquals(303, cb.status());
            assertEquals("no-store", cb.header("Cache-Control"));
            assertEquals("no-referrer", cb.header("Referrer-Policy"));
            if (good) {
                assertEquals("/dashboard", cb.header("Location"));
                assertTrue(cb.headers().get("Set-Cookie").contains("app_session=fresh; Path=/; HttpOnly; Secure"));
                assertEquals(FlowType.WEB2APP, e.ids.get(0).flowType());
                // replay of the completed callback
                EidLoginResponse again = e.get("/auth/eid/callback?sessionId=" + SID + "&userChallengeVerifier=" + v, cookie);
                assertEquals("/login?eid_error=expired", again.header("Location"));
                assertEquals(1, e.ids.size());
            } else {
                assertEquals("/login?eid_error=VALIDATION", cb.header("Location"));
                assertTrue(e.ids.isEmpty());
                assertEquals("validation", e.events.get(e.events.size() - 1).meta().get("reason"));
            }
        }
    }

    // Go TestStatusBinding + TestCSRF + method refusals
    @Test
    public void bindingCrossSiteAndMethods() {
        Env e = new Env(null, null);
        String cookie = loginCookie(e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
        String other = cookie.substring(0, cookie.length() - 1) + (cookie.endsWith("x") ? "y" : "x");
        for (String c : new String[] {null, "eid_login=" + SID + "." + "A".repeat(43), other, "eid_login=" + SID, "eid_login=x.y"}) {
            EidLoginResponse r = e.get("/auth/eid/status", c);
            assertEquals(String.valueOf(c), "EXPIRED", body(r).get("state"));
        }
        assertEquals("PENDING", body(e.get("/auth/eid/status", cookie)).get("state"));
        assertEquals(403, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", Map.of("Sec-Fetch-Site", "cross-site")).status());
        Map<String, List<String>> xs = Map.of("Sec-Fetch-Site", List.of("cross-site"));
        assertEquals(403, e.login.handle(EidLoginRequest.of("GET", "/auth/eid/start?mode=web2app", xs, null, null)).status());
        for (String ok : new String[] {"same-origin", "same-site", "none"}) {
            assertEquals(ok, 200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", Map.of("Sec-Fetch-Site", ok)).status());
        }
        assertEquals(415, e.post("/auth/eid/start", "mode=qr", Map.of("Content-Type", "application/x-www-form-urlencoded")).status());
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", Map.of("Content-Type", "Application/JSON; charset=utf-8")).status());
        assertEquals(405, e.get("/auth/eid/start?mode=qr", null).status());
        assertEquals(405, e.login.handle(EidLoginRequest.of("PUT", "/auth/eid/start", Map.of(), "{}", null)).status());
        assertEquals(405, e.post("/auth/eid/status", "{}", null).status());
        assertEquals(405, e.post("/auth/eid/callback", "{}", null).status());
        assertEquals(404, e.get("/auth/eid/other", null).status());
        for (String bad : new String[] {"{", "[1]", "{\"mode\":1}", "\"qr\"", "{\"mode\":\"qr\"} x", "{\"mode\":\"qr\",\"pad\":\"" + "a".repeat(5000) + "\"}"}) {
            assertEquals(bad.length() > 60 ? "too large" : bad, "invalid_body", body(e.post("/auth/eid/start", bad, null)).get("error"));
        }
        assertEquals("invalid_mode", body(e.post("/auth/eid/start", "null", null)).get("error"));
    }

    // Go TestMemoryStoreCap + TestWindowLimiterFullFailsClosed + TestDefaultStartLimit
    @Test
    public void storeCapAndLimiter() {
        FakeClock clock = new FakeClock(NOW);
        EidLoginStore s = EidLoginStore.memory(2, clock);
        s.set(new EidLoginTx("a", "", "qr", NOW, "", null, null, false), Duration.ofMinutes(1));
        s.set(new EidLoginTx("b", "", "qr", NOW, "", null, null, false), Duration.ofMillis(1));
        clock.advance(Duration.ofMillis(5));
        s.set(new EidLoginTx("c", "", "qr", NOW, "", null, null, false), Duration.ofMinutes(1));
        try {
            s.set(new EidLoginTx("d", "", "qr", NOW, "", null, null, false), Duration.ofMinutes(1));
            fail("full");
        } catch (EidLoginStore.StoreFullException expected) {
            // ok
        }
        s.set(new EidLoginTx("a", "", "push", NOW, "", null, null, false), Duration.ofMinutes(1));
        assertEquals("push", s.get("a").mode());
        assertTrue(s.delete("a"));
        assertFalse(s.delete("a"));

        Env full = new Env(b -> b.store(new EidLoginStore() {
            @Override
            public EidLoginTx get(String id) {
                return null;
            }

            @Override
            public void set(EidLoginTx tx, Duration ttl) {
                throw new EidLoginStore.StoreFullException();
            }

            @Override
            public boolean delete(String id) {
                return false;
            }
        }), null);
        EidLoginResponse busy = full.post("/auth/eid/start", "{\"mode\":\"qr\"}", null);
        assertEquals(503, busy.status());
        assertEquals("busy", body(busy).get("error"));
        assertEquals("30", busy.header("Retry-After"));

        Predicate<String> lim = EidLogin.windowLimiter(1, Duration.ofMillis(50), 3, clock);
        assertTrue(lim.test("push:victim"));
        assertFalse(lim.test("push:victim"));
        assertTrue(lim.test("a"));
        assertTrue(lim.test("b"));
        assertTrue("full — a new key is counted in the overflow bucket (review S4; Go refuses it)", lim.test("c"));
        assertFalse("the victim's counter survives", lim.test("push:victim"));
        clock.advance(Duration.ofMillis(60));
        assertTrue("passed windows are dropped", lim.test("c"));

        String[] ip = {"192.0.2.1"};
        Env e = new Env(b -> b.clientIp(r -> ip[0]), null);
        for (int i = 0; i < 20; i++) assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        EidLoginResponse lr = e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null);
        assertEquals(429, lr.status());
        assertEquals("60", lr.header("Retry-After"));
        ip[0] = "192.0.2.2";
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        Env off = new Env(b -> b.clientIp(r -> "192.0.2.1").rateLimits(Map.of("start", EidLogin.RateRule.unlimited())), null);
        for (int i = 0; i < 25; i++) assertEquals(200, off.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        try {
            new Env(b -> b.rateLimits(Map.of("other", EidLogin.RateRule.of(1, Duration.ofSeconds(1)))), null);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    // Go TestForwardedClientIP + TestForwardedClientIPRateLimit + TestWithReturnHint + TestConfig
    @Test
    public void clientIpHintAndConfig() {
        Map<String, List<String>> h = new LinkedHashMap<>();
        h.put("X-Forwarded-For", List.of("198.51.100.7, 10.0.0.3", "10.0.0.2"));
        h.put("x-real-ip", List.of("10.0.0.9"));
        EidLoginRequest r = EidLoginRequest.of("GET", "/", h, null, "10.0.0.1");
        String[] want = {"10.0.0.2", "10.0.0.3", "198.51.100.7", ""};
        for (int hops = 1; hops <= 4; hops++) assertEquals("hops " + hops, want[hops - 1], EidLogin.forwardedClientIp(hops).apply(r));
        EidLoginRequest noXff = EidLoginRequest.of("GET", "/", Map.of("X-Real-IP", List.of("10.0.0.9")), null, null);
        assertEquals("10.0.0.9", EidLogin.forwardedClientIp(1).apply(noXff));
        try {
            EidLogin.forwardedClientIp(0);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        List<String> keys = new ArrayList<>();
        Env e = new Env(b -> b.clientIp(EidLogin.forwardedClientIp(1)).rateLimit(k -> {
            keys.add(k);
            return true;
        }), null);
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", Map.of("X-Forwarded-For", "1.2.3.4, 198.51.100.7")).status());
        assertEquals(List.of("start:198.51.100.7"), keys);

        String cb = "https://bank.example.mn/auth/eid/callback";
        assertEquals(cb + "?retScheme=googlechromes", EidLogin.withReturnHint(cb,
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0 Mobile/15E148 Safari/604.1"));
        assertEquals(cb + "?retPkg=com.sec.android.app.sbrowser", EidLogin.withReturnHint(cb,
            "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36 SamsungBrowser/24.0"));
        assertEquals(cb, EidLogin.withReturnHint(cb, "Mozilla/5.0 (Macintosh) Safari/605"));

        EidClient c = EidClient.builder(new Credentials(RP_UUID, "Демо банк", "s")).build();
        for (String bad : new String[] {"https://bank.mn/eid/cb", "http://bank.mn/auth/eid/callback", "https:///auth/eid/callback"}) {
            try {
                EidLogin.builder(c).onSuccess((id, req) -> null).callbackUrl(bad).build();
                fail(bad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        try {
            EidLogin.builder(c).build();
            fail("onSuccess required");
        } catch (NullPointerException expected) {
            // ok
        }
        Env noCb = new Env(b -> b.callbackUrl(""), null);
        assertEquals("web2app_not_configured", body(noCb.get("/auth/eid/start?mode=web2app", null)).get("error"));
        assertEquals("invalid_id", body(noCb.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"abc\"}", null)).get("error"));
        assertEquals("УБ12345678", EidLogin.normaliseId(" уб 1234 5678\t"));
    }

    // Go TestEvents + TestPushTimeoutLooksLikeDecoy + qr-session-gone (status paths without a signature)
    @Test
    public void endResultsAndEvents() {
        String[][] ends = {{"USER_REFUSED", "refused", "FAILED"}, {"WRONG_VC", "failed", "FAILED"}, {"TIMEOUT", "expired", "FAILED"}};
        for (String[] end : ends) {
            Env e = new Env(null, null);
            String cookie = loginCookie(e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
            e.fake.session = "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"" + end[0] + "\"}}";
            Map<String, Object> b = body(e.get("/auth/eid/status", cookie));
            assertEquals(end[2], b.get("state"));
            assertEquals(end[0], b.get("error"));
            assertEquals(end[1], e.events.get(0).kind().wireName());
            assertEquals(SID, e.events.get(0).sessionId());
        }
        Env p = new Env(null, null);
        String pc = loginCookie(p.post("/auth/eid/start", "{\"mode\":\"push\",\"idCode\":\"УБ12345678\"}", null));
        p.fake.session = "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"TIMEOUT\"}}";
        assertEquals("a real push TIMEOUT looks like a decoy", "EXPIRED", body(p.get("/auth/eid/status", pc)).get("state"));

        Env g = new Env(null, null);
        String gc = loginCookie(g.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
        g.fake.sessionStatus = 503;
        assertEquals(502, g.get("/auth/eid/status", gc).status());
        g.fake.sessionStatus = 404;
        assertEquals("EXPIRED", body(g.get("/auth/eid/status", gc)).get("state"));
        assertEquals(EidLoginEvent.Kind.EXPIRED, g.events.get(0).kind());
    }

    // Review S1 / S5: N concurrent status calls for one completed session → onSuccess exactly once; a status call while
    // another one for the same session is waiting on eID answers PENDING at once (per-session single flight).
    @Test
    public void concurrentStatusSucceedsOnceAndSingleFlight() throws Exception {
        Env e = vectorEnv("auth-pss-sha512-qr", null);
        String saved = e.fake.session;
        e.fake.session = "{\"state\":\"RUNNING\"}";
        String cookie = loginCookie(e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
        e.fake.session = saved;
        int n = 16;
        java.util.concurrent.CountDownLatch gate = new java.util.concurrent.CountDownLatch(1);
        e.fake.sessionGate = gate;
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(n);
        try {
            java.util.concurrent.CyclicBarrier go = new java.util.concurrent.CyclicBarrier(n);
            List<java.util.concurrent.Future<String>> fs = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                fs.add(pool.submit(() -> {
                    go.await(10, java.util.concurrent.TimeUnit.SECONDS);
                    return (String) body(e.get("/auth/eid/status", cookie)).get("state");
                }));
            }
            // Every caller but the one waiting on eID returns PENDING without waiting.
            long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
            while (fs.stream().filter(java.util.concurrent.Future::isDone).count() < n - 1 && System.nanoTime() < deadline) {
                Thread.onSpinWait();
            }
            assertEquals("all but one answered while eID was still being polled", n - 1, fs.stream().filter(java.util.concurrent.Future::isDone).count());
            gate.countDown();
            List<String> states = new ArrayList<>();
            for (java.util.concurrent.Future<String> f : fs) states.add(f.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(states.toString(), 1, states.stream().filter("OK"::equals).count());
            assertEquals(states.toString(), n - 1, states.stream().filter("PENDING"::equals).count());
        } finally {
            gate.countDown();
            pool.shutdownNow();
        }
        e.fake.sessionGate = null;
        assertEquals("onSuccess ran exactly once", 1, e.ids.size());

        // No gate: a burst of concurrent calls still completes the sign-in exactly once (store.delete decides).
        Env b = vectorEnv("auth-pss-sha512-qr", null);
        b.fake.session = "{\"state\":\"RUNNING\"}";
        String c2 = loginCookie(b.post("/auth/eid/start", "{\"mode\":\"qr\"}", null));
        b.fake.session = saved;
        java.util.concurrent.ExecutorService pool2 = java.util.concurrent.Executors.newFixedThreadPool(n);
        try {
            java.util.concurrent.CyclicBarrier go = new java.util.concurrent.CyclicBarrier(n);
            List<java.util.concurrent.Future<String>> fs = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                fs.add(pool2.submit(() -> {
                    go.await(10, java.util.concurrent.TimeUnit.SECONDS);
                    return (String) body(b.get("/auth/eid/status", c2)).get("state");
                }));
            }
            List<String> states = new ArrayList<>();
            for (java.util.concurrent.Future<String> f : fs) states.add(f.get(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(states.toString(), 1, states.stream().filter("OK"::equals).count());
        } finally {
            pool2.shutdownNow();
        }
        assertEquals(1, b.ids.size());
    }

    // Review S5: the Web2App callback with the matching session id but an empty or missing userChallengeVerifier is
    // refused by EidLogin (unbound) AND by the validator (AUTH_VERIFIER_REQUIRED) — both layers pinned.
    @Test
    public void web2AppCallbackWithoutVerifierRefused() {
        for (String q : new String[] {"&userChallengeVerifier=", ""}) {
            Env e = vectorEnv("auth-web2app-verifier", null);
            String saved = e.fake.session;
            e.fake.session = "{\"state\":\"RUNNING\"}";
            String cookie = loginCookie(e.get("/auth/eid/start?mode=web2app", null));
            e.fake.session = saved;
            EidLoginResponse cb = e.get("/auth/eid/callback?sessionId=" + SID + q, cookie);
            assertEquals(303, cb.status());
            assertEquals("/login?eid_error=unbound", cb.header("Location"));
            assertTrue(e.ids.isEmpty());
            assertEquals("unbound", e.events.get(e.events.size() - 1).meta().get("reason"));
        }
        Map<String, Object> c = rpCase("auth-web2app-verifier");
        @SuppressWarnings("unchecked")
        EidClient client = TestAccess.clock(EidClient.builder(new Credentials(RP_UUID, "Тест банк", "rp_sk_test"))
            .baseUrl("https://rp-api.conformance.test").transport(new Fake()).trust(trust((Map<String, Object>) c.get("$trust"))),
            new FakeClock(NOW)).build();
        mn.eidmongolia.eid.SessionResult res = mn.eidmongolia.eid.SessionService.parseSessionResult(LoginJson.stringify(c.get("session")));
        AcspContext a = acsp(EidLoginConformanceTest.obj(c.get("acsp")));
        for (String v : new String[] {null, ""}) {
            try {
                client.validator().validateAuth(res, a, mn.eidmongolia.eid.ValidateAuthOptions.builder().expectedFlowType(FlowType.WEB2APP)
                    .userChallengeVerifier(v).build());
                fail("verifier " + v);
            } catch (mn.eidmongolia.eid.EidException.Validation x) {
                assertEquals(mn.eidmongolia.eid.ValidationReasons.AUTH_VERIFIER_REQUIRED, x.reason());
            }
        }
    }

    // Review S3 / S4: no IP from anywhere → no limit (warned once; the corpus pins it); a builder clientIp that answers ""
    // → the shared start:unknown bucket; IPv6 keyed by /64; a full limiter table → the overflow bucket, counters kept.
    @Test
    public void clientIpBucketsAndLimiterOverflow() {
        List<String> keys = new ArrayList<>();
        List<String> warnings = Collections.synchronizedList(new ArrayList<>());
        System.Logger logger = new System.Logger() {
            @Override
            public String getName() {
                return "test";
            }

            @Override
            public boolean isLoggable(Level level) {
                return true;
            }

            @Override
            public void log(Level level, java.util.ResourceBundle bundle, String msg, Throwable thrown) {
                if (level == Level.WARNING) warnings.add(msg);
            }

            @Override
            public void log(Level level, java.util.ResourceBundle bundle, String format, Object... params) {
                if (level == Level.WARNING) warnings.add(format);
            }
        };
        Env none = new Env(b -> b.logger(logger).rateLimit(k -> {
            keys.add(k);
            return true;
        }), null);
        for (int i = 0; i < 3; i++) assertEquals(200, none.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        assertTrue("no start key without any IP: " + keys, keys.isEmpty());
        assertEquals("warned once: " + warnings, 1, warnings.stream().filter(w -> w.contains("client IP")).count());

        String[] ip = {""};
        Env e = new Env(b -> b.clientIp(r -> ip[0]).rateLimit(k -> {
            keys.add(k);
            return true;
        }), null);
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        ip[0] = "2001:db8:1:2:aaaa:bbbb:cccc:dddd";
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        ip[0] = "::ffff:192.0.2.9";
        assertEquals(200, e.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        assertEquals(List.of("start:unknown", "start:2001:db8:1:2::/64", "start:192.0.2.9"), keys);
        assertEquals("2001:db8:1:2::/64", EidLogin.ipKey("[2001:db8:1:2::1%eth0]"));
        assertEquals("not an IP literal: unchanged, never resolved", "host:name", EidLogin.ipKey("host:name"));
        // The unknown bucket is limited like any IP: 20 per minute shared by every client without an address.
        Env u = new Env(b -> b.clientIp(r -> ""), null);
        for (int i = 0; i < 20; i++) assertEquals(200, u.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());
        assertEquals(429, u.post("/auth/eid/start", "{\"mode\":\"qr\"}", null).status());

        FakeClock clock = new FakeClock(NOW);
        Predicate<String> lim = EidLogin.windowLimiter(1, Duration.ofMillis(50), 3, clock);
        assertTrue(lim.test("push:victim"));
        assertTrue(lim.test("a"));
        assertTrue(lim.test("b"));
        assertTrue("full — a new key goes to the overflow bucket", lim.test("c"));
        assertFalse("the overflow bucket is limited too", lim.test("d"));
        assertFalse("the victim's counter survives", lim.test("push:victim"));
        clock.advance(Duration.ofMillis(60));
        assertTrue("passed windows are dropped", lim.test("e"));
    }

    // Review: toString of a request never prints the Cookie value, the body or the callback's query.
    @Test
    public void requestToStringRedacted() {
        EidLoginRequest r = EidLoginRequest.of("GET", "/auth/eid/callback?sessionId=" + SID + "&userChallengeVerifier=secret-verifier",
            Map.of("Cookie", List.of("eid_login=" + SID + ".binding-secret")), "{\"idCode\":\"УБ12345678\"}", "192.0.2.1");
        String s = r.toString();
        assertFalse(s, s.contains("binding-secret") || s.contains("secret-verifier") || s.contains("УБ12345678") || s.contains(SID));
        assertTrue(s, s.contains("/auth/eid/callback") && s.contains("Cookie"));
    }

    // Review: a store failure on the callback redirects (303 eid_error=internal, Go) instead of a JSON 500.
    @Test
    public void callbackStoreErrorRedirects() {
        Env e = new Env(b -> b.store(new EidLoginStore() {
            @Override
            public EidLoginTx get(String id) {
                throw new IllegalStateException("redis down");
            }

            @Override
            public void set(EidLoginTx tx, Duration ttl) {
            }

            @Override
            public boolean delete(String id) {
                return false;
            }
        }), null);
        EidLoginResponse cb = e.get("/auth/eid/callback?sessionId=" + SID + "&userChallengeVerifier=x", "eid_login=" + SID + "." + "A".repeat(43));
        assertEquals(303, cb.status());
        assertEquals("/login?eid_error=internal", cb.header("Location"));
        assertEquals(500, e.get("/auth/eid/status", "eid_login=" + SID + "." + "A".repeat(43)).status());
    }
}
