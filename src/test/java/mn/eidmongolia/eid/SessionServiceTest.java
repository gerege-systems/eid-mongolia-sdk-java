package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

/** SessionService: poll / waitForResult with a fake clock, the deadline rule, parsing, requireOk. */
public class SessionServiceTest {
    /**
     * A fake RP-API whose long-poll "takes" the requested timeoutMs on the fake clock and answers RUNNING until
     * {@code completeAfter} polls; discovery answers {@code discovery}.
     */
    static FakeRp longPoll(int completeAfter, String complete, int discoveryStatus, String discovery) {
        FakeRp[] rp = new FakeRp[1];
        int[] n = {0};
        rp[0] = new FakeRp(r -> {
            if (FakeRp.path(r).equals("/.well-known/eid")) return FakeRp.json(discoveryStatus, discovery);
            String q = r.uri().getRawQuery();
            long ms = Long.parseLong(q.substring(q.indexOf('=') + 1));
            assertEquals("HTTP timeout = serverPoll + 10 s", Duration.ofMillis(ms).plusSeconds(10), r.timeout());
            rp[0].clock.advance(Duration.ofMillis(ms));
            return FakeRp.json(200, ++n[0] >= completeAfter ? complete : "{\"state\":\"RUNNING\"}");
        });
        return rp[0];
    }

    static List<Long> polls(FakeRp rp) {
        List<Long> out = new ArrayList<>();
        for (EidHttpRequest r : rp.seen) {
            String q = r.uri().getRawQuery();
            if (q != null) out.add(Long.parseLong(q.substring(q.indexOf('=') + 1)));
        }
        return out;
    }

    // Go client_test.go TestSession_PollAndWait
    @Test
    public void pollAndWait() {
        FakeRp rp = longPoll(3, "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\"}}", 200, "{\"sessionTtl\":{\"auth\":300,\"sign\":600}}");
        SessionResult r = rp.client().session().waitForResult("abc/def", WaitOptions.builder().serverPoll(Duration.ofSeconds(2)).build());
        assertEquals(SessionResult.STATE_COMPLETE, r.state());
        assertEquals(List.of(2000L, 2000L, 2000L), polls(rp));
        assertEquals("/session/abc%2Fdef", FakeRp.path(rp.last()));
        assertEquals("GET", rp.last().method());
        assertEquals("/.well-known/eid", FakeRp.path(rp.seen.get(0)));

        // maxWait passes → the last RUNNING is returned without an error.
        rp = longPoll(Integer.MAX_VALUE, "", 200, "{}");
        r = rp.client().session().waitForResult("x", WaitOptions.builder().maxWait(Duration.ofMillis(10)).build());
        assertEquals(SessionResult.STATE_RUNNING, r.state());
        assertEquals("one poll of at least 1 s", List.of(1000L), polls(rp));
    }

    // Go client_test.go TestWaitDeadline — expiresAt → discovery sessionTtl → 600 s.
    @Test
    public void waitDeadline() {
        FakeRp rp = FakeRp.reply(200, "{\"sessionTtl\":{\"auth\":300,\"sign\":600}}");
        SessionService s = rp.client().session();
        Instant now = rp.clock.instant();
        assertEquals("discovery max(auth, sign) + grace", now.plusSeconds(600).plus(SessionService.WAIT_GRACE), s.waitDeadline(WaitOptions.DEFAULTS));
        assertEquals("/.well-known/eid", FakeRp.path(rp.last()));
        int n = rp.seen.size();
        Instant exp = now.plusSeconds(280);
        assertEquals("expiresAt + grace", exp.plus(SessionService.WAIT_GRACE), s.waitDeadline(WaitOptions.builder().expiresAt(exp).build()));
        assertEquals("past expiresAt → one poll", now.plusSeconds(1), s.waitDeadline(WaitOptions.builder().expiresAt(now.minusSeconds(3600)).build()));
        assertEquals("maxWait wins", now.plusSeconds(42),
            s.waitDeadline(WaitOptions.builder().maxWait(Duration.ofSeconds(42)).expiresAt(exp).build()));
        assertEquals("expiresAt / maxWait → no discovery", n, rp.seen.size());
        // older CA (no sessionTtl) or discovery down → DEFAULT_MAX_WAIT (600 s)
        for (FakeRp f : new FakeRp[] {FakeRp.reply(200, "{\"version\":\"v3\"}"), FakeRp.reply(503, "{}")}) {
            assertEquals(f.clock.instant().plus(SessionService.DEFAULT_MAX_WAIT), f.client().session().waitDeadline(WaitOptions.DEFAULTS));
        }
    }

    /** The deadline from expiresAt drives the number and length of the polls (fake clock). */
    @Test
    public void waitForResultTimingFromExpiresAt() {
        FakeRp rp = longPoll(Integer.MAX_VALUE, "", 200, "{}");
        Instant exp = rp.clock.instant().plusSeconds(60); // deadline = +75 s
        SessionResult r = rp.client().session().waitForResult("s", WaitOptions.builder().expiresAt(exp).build());
        assertEquals(SessionResult.STATE_RUNNING, r.state());
        assertEquals("30 + 30 + 15 s, no discovery", List.of(30_000L, 30_000L, 15_000L), polls(rp));
        assertEquals(3, rp.seen.size());

        // completes on the second poll: stops there
        rp = longPoll(2, "{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"USER_REFUSED\"}}", 200, "{}");
        r = rp.client().session().waitForResult("s", WaitOptions.builder().expiresAt(rp.clock.instant().plusSeconds(300)).build());
        assertEquals("USER_REFUSED", r.endResult());
        assertEquals(2, rp.seen.size());
        try {
            SessionService.requireOk(r);
            fail();
        } catch (EidException.SessionFailed e) {
            assertEquals("USER_REFUSED", e.endResult());
            assertEquals("USER_REFUSED", e.code());
        }

        // no expiresAt: discovery 300/600 → 615 s
        rp = longPoll(Integer.MAX_VALUE, "", 200, "{\"sessionTtl\":{\"auth\":300,\"sign\":600}}");
        rp.client().session().waitForResult("s", null);
        long total = 0;
        for (long ms : polls(rp)) total += ms;
        assertEquals(615_000L, total);
    }

    @Test
    public void errorsPropagate() {
        FakeRp rp = new FakeRp(r -> FakeRp.path(r).startsWith("/session/") ? FakeRp.json(401, "{\"error\":\"bad\"}") : FakeRp.json(200, "{}"));
        try {
            rp.client().session().waitForResult("s", WaitOptions.builder().maxWait(Duration.ofSeconds(5)).build());
            fail();
        } catch (EidException.Authentication expected) {
            // ok
        }
    }

    // Go validator.go sessionDone
    @Test
    public void requireOk() {
        SessionResult ok = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\"}}");
        assertEquals(ok, SessionService.requireOk(ok));
        try {
            SessionService.requireOk(SessionService.parseSessionResult("{\"state\":\"RUNNING\"}"));
            fail();
        } catch (EidException.Validation expected) {
            // ok
        }
        try {
            SessionService.requireOk(SessionService.parseSessionResult("{\"state\":\"COMPLETE\"}"));
            fail();
        } catch (EidException.SessionFailed e) {
            assertEquals("UNKNOWN", e.endResult());
        }
        try {
            SessionService.requireOk(null);
            fail();
        } catch (EidException.Validation expected) {
            // ok
        }
    }

    // Go client_test.go TestParseSessionResult (the rest is in rp-wire-local.json)
    @Test
    public void parseOnBehalfOfAndCallback() {
        SessionResult r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"signature\":{\"initialCallbackUrl\":\"\"},"
            + "\"onBehalfOf\":{\"orgEtsi\":\"NTRMN-6235972\",\"orgName\":\"Герэге Системс ХХК\"}}");
        assertEquals("", r.initialCallbackUrl());
        assertEquals("NTRMN-6235972", r.onBehalfOf().orgEtsi());
        assertEquals("", r.onBehalfOf().rightType());
        r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\"},"
            + "\"onBehalfOf\":{\"orgEtsi\":\"NTRMN-6235972\",\"orgName\":\"Гэрэгэ Системс ХХК\",\"role\":\"ceo\",\"rightType\":\"ADMIN\","
            + "\"roleLabel\":\"Гүйцэтгэх захирал\",\"rightTypeLabel\":\"Админ\"}}");
        assertEquals("ADMIN", r.onBehalfOf().rightType());
        assertEquals("Гүйцэтгэх захирал", r.onBehalfOf().roleLabel());
        assertEquals("Админ", r.onBehalfOf().rightTypeLabel());
        r = SessionService.parseSessionResult("{\"state\":\"RUNNING\",\"onBehalfOf\":{\"orgName\":\"x\"}}");
        assertNull(r.onBehalfOf());
        assertNull(r.initialCallbackUrl());
        // signatureProtocol inside signature (older CA); params without hashAlgorithm → null
        r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"signature\":{\"signatureProtocol\":\"RAW_DIGEST_SIGNATURE\","
            + "\"signatureAlgorithmParameters\":{\"saltLength\":32}}}");
        assertEquals("RAW_DIGEST_SIGNATURE", r.signatureProtocol());
        assertNull(r.signatureAlgorithmParameters());
        r = SessionService.parseSessionResult("{\"signature\":{\"signatureAlgorithmParameters\":{\"hashAlgorithm\":\"SHA-256\"}},"
            + "\"presentation\":{\"jws\":\"a.b.c\"}}");
        assertNull("saltLength absent", r.signatureAlgorithmParameters().saltLength());
        assertEquals("", r.signatureAlgorithmParameters().maskGenAlgorithm());
        assertEquals("a.b.c", r.presentationJws());
    }

    // Go portal_gaps_test.go TestSessionPersonNationality, TestSessionPersonRawToken (empty blocks)
    @Test
    public void parsePersonBlocks() {
        SessionResult r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\"},\"person\":{\"civilId\":\"1\",\"nationality\":\"XXA\"}}");
        assertEquals("XXA", r.person().nationality());
        assertEquals("1", r.person().civilId());
        r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"person\":{\"civilId\":\"1\"}}");
        assertEquals("", r.person().nationality());
        assertNull(SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"person\":{}}").person());
        r = SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"person\":{\"nationality\":\"MNG\"}}");
        assertEquals("MNG", r.person().nationality());
        r = SessionService.parseSessionResult("{\"state\":\"RUNNING\",\"person\":{},\"tokenCertificate\":{}}");
        assertNull(r.person());
        assertNull(r.tokenCertificate());
        String raw = "{\"state\":\"COMPLETE\",\"futureField\":1}";
        assertEquals(raw, SessionService.parseSessionResult(raw).rawJson());
    }

    @Test
    public void parseRejectsNonObject() {
        for (String bad : new String[] {"[]", "\"x\"", "{", ""}) {
            try {
                SessionService.parseSessionResult(bad);
                fail(bad);
            } catch (EidException expected) {
                // ok
            }
        }
    }

    // Go TestSessionPersonRawToken (Poll — Raw filled); empty body → empty result
    @Test
    public void pollRawAndEmpty() {
        String raw = "{\"state\":\"COMPLETE\",\"person\":{\"geID\":42}}";
        FakeRp rp = FakeRp.reply(200, raw);
        SessionResult r = rp.client().session().poll("s1", Duration.ofSeconds(1));
        assertEquals(raw, r.rawJson());
        assertEquals(42, r.person().geId());
        assertEquals("timeoutMs=1000", rp.last().uri().getRawQuery());
        rp = FakeRp.reply(200, "");
        r = rp.client().session().poll("s1", null);
        assertEquals("", r.state());
        assertEquals("timeoutMs=30000", rp.last().uri().getRawQuery());
        assertEquals(Duration.ofSeconds(40), rp.last().timeout());
        assertNotNull(r);
        assertTrue(r.rawJson().isEmpty());
    }
}
