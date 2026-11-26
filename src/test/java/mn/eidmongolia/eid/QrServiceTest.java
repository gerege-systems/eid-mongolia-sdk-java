package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import mn.eidmongolia.eid.pades.EidQr;
import mn.eidmongolia.eid.pades.EidQrException;
import org.junit.Test;

/**
 * QrService (RP-API «My QR» client) against the fake RP-API, driven by the CA's My QR vectors
 * (src/test/resources/myqr_vectors.json, case ok_basic): ports of Go qr_test.go TestQRStartResult, TestQRStartErrors,
 * TestQRResultFailures (.NET EidQrClient tests).
 */
public class QrServiceTest {
    static final Json.Obj V = (Json.Obj) Json.parse(TestRes.resource("myqr_vectors.json"));
    static final String TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";

    static Json.Obj okCase() {
        for (Object o : V.optArr("verify")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals("ok_basic")) return c;
        }
        throw new AssertionError("ok_basic");
    }

    static List<X509Certificate> pems(List<Object> l) throws Exception {
        List<X509Certificate> out = new ArrayList<>();
        for (Object p : l) {
            out.add((X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(((String) p).getBytes(StandardCharsets.US_ASCII))));
        }
        return out;
    }

    /** A fake CA: start → sid, session → [state]/[end] with the vector's JWS; [gone] → 410. */
    static final class Stub {
        String state = "COMPLETE";
        String end = "OK";
        boolean gone;
        String jws;
        final FakeRp rp;
        final EidClient client;
        final Json.Obj exp;

        Stub() throws Exception {
            Json.Obj c = okCase();
            exp = c.optObj("expect");
            jws = c.optString("jws");
            Json.Obj rev = c.optObj("revocation");
            Json.Obj t = V.optObj("trust");
            List<String> skis = new ArrayList<>();
            for (Object s : t.optArr("allowedIssuerSkis")) skis.add((String) s);
            EidQr.Trust trust = new EidQr.Trust(pems(t.optArr("anchorsPem")), pems(t.optArr("intermediatesPem")), skis,
                (leaf, iss) -> rev.optString(leaf.getSerialNumber().toString(16)), false);
            rp = new FakeRp(q -> {
                String p = FakeRp.path(q);
                if (p.equals("/authentication/qr")) {
                    String qr = ((Json.Obj) Json.parse(q.body())).optString("qr");
                    if (qr.endsWith("NOCERT")) return FakeRp.json(409, "{\"error\":\"x\",\"code\":\"NO_SIGNING_CERTIFICATE\"}");
                    if (qr.endsWith("INVALID")) return FakeRp.json(404, "{\"error\":\"x\",\"code\":\"QR_TOKEN_INVALID\"}");
                    if (qr.endsWith("DENIED")) return FakeRp.json(403, "{\"error\":\"x\",\"code\":\"PERMISSION_DENIED\"}");
                    return FakeRp.json(200, "{\"sessionID\":\"" + exp.optString("sessionId") + "\"}");
                }
                if (gone) return FakeRp.json(410, "{\"error\":\"gone\",\"code\":\"SESSION_GONE\"}");
                return FakeRp.json(200, "{\"state\":\"" + state + "\",\"result\":{\"endResult\":\"" + end + "\"},\"presentation\":{\"jws\":\"" + jws + "\"}}");
            });
            rp.clock.now = Instant.ofEpochSecond(exp.optLong("now", 0));
            client = EidClient.builder(new Credentials(exp.optString("rpUUID"), "Касс", "rp_sk_x")).transport(rp).clock(rp.clock)
                .qrIssuer(V.optString("issuer")).qrTrust(trust).build();
        }
    }

    static String tok(String suffix) {
        return TOKEN.substring(0, 43 - suffix.length()) + suffix;
    }

    // Go TestQRStartResult
    @Test
    public void startResultCheck() throws Exception {
        Stub s = new Stub();
        QrSession sess = s.client.qr().start(new QrStartRequest(" " + EidQr.PREFIX + TOKEN + "\n"));
        FakeRp.assertRequest(s.rp.last(), "POST", "/authentication/qr");
        Json.Obj body = s.rp.lastJson();
        assertEquals(4, body.keySet().size());
        assertEquals(EidQr.PREFIX + TOKEN, body.optString("qr"));
        assertEquals(s.exp.optString("rpUUID"), body.optString("relyingPartyUUID"));
        assertEquals("Касс", body.optString("relyingPartyName"));
        assertEquals(sess.nonce(), body.optString("nonce"));
        assertEquals(22, sess.nonce().length());
        assertEquals(16, Base64.getUrlDecoder().decode(sess.nonce()).length);
        assertEquals(s.exp.optString("sessionId"), sess.sessionId());

        // The vector's JWS carries the vector's nonce: the RP's own nonce / sub-system name.
        sess = s.client.qr().start(new QrStartRequest(EidQr.PREFIX + TOKEN, s.exp.optString("nonce"), "Касс 3"));
        assertEquals("Касс 3", s.rp.lastJson().optString("relyingPartyName"));
        EidQr.Result r = s.client.qr().result(sess, WaitOptions.builder().maxWait(Duration.ofSeconds(5)).build());
        assertEquals(okCase().optObj("result").optString("sha256"), r.sha256());
        assertEquals(okCase().optObj("result").optObj("signer").optString("etsi"), r.signer().etsi());
        assertTrue(s.rp.last().uri().toString().contains("/session/" + s.exp.optString("sessionId")));

        QrCheck chk = s.client.qr().check(sess, null);
        assertTrue(chk.complete());
        assertEquals(r.sha256(), chk.presentation().sha256());
        assertTrue("serverPoll ≤ 0 → 1 s", s.rp.last().uri().getRawQuery().contains("timeoutMs=1000"));
        // A stored presentation verifies against the stored session.
        assertEquals(r.sha256(), s.client.qr().verify(s.jws, sess).sha256());
    }

    // Go TestQRStartErrors
    @Test
    public void startErrors() throws Exception {
        Stub s = new Stub();
        for (String q : new String[] {TOKEN, "hello", EidQr.PREFIX + "short", "EIDMN-QR2:" + TOKEN}) {
            try {
                s.client.qr().start(new QrStartRequest(q));
                fail(q);
            } catch (EidQrException e) {
                assertEquals(EidQrException.FORMAT_INVALID, e.code());
            }
        }
        assertEquals("client-side errors never reach the CA", 0, s.rp.seen.size());
        try {
            s.client.qr().start(new QrStartRequest(EidQr.PREFIX + tok("NOCERT")));
            fail();
        } catch (EidException.NoSigningCertificate e) {
            assertEquals(409, e.status());
        }
        try {
            s.client.qr().start(new QrStartRequest(EidQr.PREFIX + tok("INVALID")));
            fail();
        } catch (EidQrException e) {
            assertEquals(EidQrException.TOKEN_INVALID, e.code());
            assertEquals(404, ((EidException) e.getCause()).status());
        }
        try {
            s.client.qr().start(new QrStartRequest(EidQr.PREFIX + tok("DENIED")));
            fail();
        } catch (EidException.Forbidden e) {
            assertEquals("PERMISSION_DENIED", e.code());
        }
    }

    // Go TestQRResultFailures
    @Test
    public void resultFailures() throws Exception {
        Stub s = new Stub();
        QrSession sess = new QrSession(s.exp.optString("sessionId"), s.exp.optString("nonce"));
        WaitOptions wo = WaitOptions.builder().maxWait(Duration.ofSeconds(2)).serverPoll(Duration.ofSeconds(1)).build();

        s.end = "USER_REFUSED";
        for (int i = 0; i < 2; i++) {
            try {
                if (i == 0) s.client.qr().result(sess, wo);
                else s.client.qr().check(sess, null);
                fail();
            } catch (EidException.SessionFailed e) {
                assertEquals("USER_REFUSED", e.endResult());
            }
        }
        s.end = "OK";

        s.gone = true;
        for (int i = 0; i < 2; i++) {
            try {
                if (i == 0) s.client.qr().result(sess, wo);
                else s.client.qr().check(sess, null);
                fail();
            } catch (EidQrException e) {
                assertEquals(EidQrException.PRESENTATION_GONE, e.code());
                assertEquals(410, ((EidException) e.getCause()).status());
            }
        }
        s.gone = false;

        s.state = "RUNNING";
        // the fake clock does not move on its own: waitForResult's deadline passes only by advancing it per poll
        s.rp.handler = withClock(s, s.rp.handler);
        try {
            s.client.qr().result(sess, wo);
            fail();
        } catch (EidQrException e) {
            assertEquals(EidQrException.PENDING, e.code());
        }
        QrCheck chk = s.client.qr().check(sess, null);
        assertFalse(chk.complete());
        assertNull(chk.presentation());
        s.state = "COMPLETE";

        // A verification failure → EidQrException — do NOT trust.
        QrSession wrongNonce = new QrSession(sess.sessionId(), "replayed-nonce-0000");
        try {
            s.client.qr().check(wrongNonce, null);
            fail();
        } catch (EidQrException e) {
            assertEquals(EidQrException.NONCE_MISMATCH, e.code());
        }
        try {
            s.client.qr().result(new QrSession("other-session", sess.nonce()), wo);
            fail();
        } catch (EidQrException e) {
            assertEquals(EidQrException.SESSION_MISMATCH, e.code());
        }
        s.jws = "";
        try {
            s.client.qr().check(sess, null);
            fail();
        } catch (EidQrException e) {
            assertEquals(EidQrException.JWS_MALFORMED, e.code());
        }
    }

    private static java.util.function.Function<EidHttpRequest, EidHttpResponse> withClock(Stub s,
        java.util.function.Function<EidHttpRequest, EidHttpResponse> h) {
        return q -> {
            s.rp.clock.advance(Duration.ofSeconds(1));
            return h.apply(q);
        };
    }
}
