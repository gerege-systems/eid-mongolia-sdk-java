package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/**
 * «Миний QR» against the CA contract vectors (`myqr_vectors.json`, contract myqr-2026-10-26, SHA-256 pinned — same file
 * as the .NET SDK): parse cases, and every verify case's error code or result (claims, data order, source, photo,
 * signer, sha256).
 */
public class QrTest {
    private static final String MYQR_VECTORS_SHA256 = "7620ad6a14bd337cd8ccb94d2d27e8f82189f5ac3ec6ece9542f8f2922b92eab";

    private static X509Certificate pem(String s) throws Exception {
        byte[] der = Cert.pemSingle(s.getBytes(StandardCharsets.US_ASCII));
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    private static List<String> strings(List<Object> a) {
        List<String> out = new ArrayList<>();
        for (Object o : a) out.add((String) o);
        return out;
    }

    @Test
    public void vectors() throws Exception {
        byte[] raw = Golden.resource("myqr_vectors.json");
        assertEquals(MYQR_VECTORS_SHA256, Text.hex(Cms.sha256(raw)));
        Json.Obj v = (Json.Obj) Json.parse(raw);
        assertEquals("myqr-2026-10-26", v.getString("contract"));
        String issuer = v.getString("issuer");
        Json.Obj t = v.getObj("trust");
        List<X509Certificate> anchors = new ArrayList<>();
        for (String p : strings(t.getArr("anchorsPem"))) anchors.add(pem(p));
        List<X509Certificate> inters = new ArrayList<>();
        for (String p : strings(t.getArr("intermediatesPem"))) inters.add(pem(p));
        List<String> skis = strings(t.getArr("allowedIssuerSkis"));

        for (Object o : v.getArr("parse")) {
            Json.Obj c = (Json.Obj) o;
            String input = c.getString("in");
            String wantErr = c.optNonEmpty("error");
            try {
                EidQr.Parsed p = EidQr.parse(input);
                assertNull(input, wantErr);
                assertEquals(input, c.getString("token"), p.token());
                if (c.has("qr")) assertEquals(input, c.getString("qr"), p.qr());
            } catch (EidQrException e) {
                assertEquals(input, wantErr, e.code());
            }
        }

        List<String> failures = new ArrayList<>();
        int n = 0;
        for (Object o : v.getArr("verify")) {
            Json.Obj c = (Json.Obj) o;
            n++;
            String name = c.getString("name");
            Json.Obj e = c.getObj("expect");
            EidQr.Expect exp = new EidQr.Expect(e.getString("rpUUID"), e.getString("sessionId"), e.getString("nonce"), issuer,
                Instant.ofEpochSecond(e.getLong("now")));
            Json.Obj rv = c.optObj("revocation");
            EidQr.RevocationCheck check = (leaf, iss) -> {
                if (rv == null) return "unknown";
                String s = rv.optString(EidQr.serialHex(leaf));
                return s.isEmpty() ? "unknown" : s;
            };
            EidQr.Trust trust = new EidQr.Trust(anchors, inters, skis, check, false);
            String wantErr = c.optNonEmpty("error");
            try {
                EidQr.Result r = EidQr.verify(c.getString("jws"), exp, trust);
                if (wantErr != null) {
                    failures.add(name + ": OK, want " + wantErr);
                    continue;
                }
                Json.Obj want = c.getObj("result");
                Json.Obj claims = (Json.Obj) Json.parse(r.claimsJson().getBytes(StandardCharsets.UTF_8));
                Json.Obj wc = want.getObj("claims");
                for (String k : wc.keys) {
                    Object w = wc.get(k);
                    Object h = claims.get(k);
                    if (w instanceof String && !w.equals(h)) failures.add(name + ": claims." + k);
                    if (w instanceof Json.Num && !(h instanceof Json.Num && ((Json.Num) h).text.equals(((Json.Num) w).text))) {
                        failures.add(name + ": claims." + k);
                    }
                }
                List<String> keys = new ArrayList<>();
                for (Map.Entry<String, String> kv : r.data()) keys.add(kv.getKey());
                if (!strings(want.getArr("dataKeys")).equals(keys)) failures.add(name + ": dataKeys");
                Json.Obj wd = want.getObj("data");
                for (String k : wd.keys) {
                    String got = null;
                    for (Map.Entry<String, String> kv : r.data()) if (kv.getKey().equals(k)) got = kv.getValue();
                    if (!wd.getString(k).equals(got)) failures.add(name + ": data." + k);
                }
                if (!want.getString("source").equals(r.source())) failures.add(name + ": source");
                Object ps = want.get("photoSha256");
                String gotPs = r.photo() == null ? null : Text.hex(Cms.sha256(r.photo()));
                if (ps instanceof String ? !ps.equals(gotPs) : gotPs != null) failures.add(name + ": photoSha256");
                Json.Obj sg = want.getObj("signer");
                if (!sg.getString("etsi").equals(r.signer().etsi())) failures.add(name + ": signer.etsi");
                if (!sg.getString("certSha256").equals(Text.hex(Cms.sha256(r.signer().certificate().getEncoded())))) {
                    failures.add(name + ": signer.certSha256");
                }
                if (!want.getString("sha256").equals(r.sha256())) failures.add(name + ": sha256");
            } catch (EidQrException x) {
                if (!x.code().equals(wantErr)) failures.add(name + ": " + x.code() + " (" + x.getMessage() + "), want " + (wantErr == null ? "OK" : wantErr));
            }
        }
        assertTrue("verify cases", n >= 38);
        assertEquals(String.join("\n", failures), 0, failures.size());
    }

    /** The default trust (embedded national root, issuer 04) rejects the test PKI's presentation. */
    @Test
    public void defaultTrustRejectsTestPki() {
        Json.Obj v = (Json.Obj) Json.parse(Golden.resource("myqr_vectors.json"));
        Json.Obj c = (Json.Obj) v.getArr("verify").get(0);
        Json.Obj e = c.getObj("expect");
        EidQr.Expect exp = new EidQr.Expect(e.getString("rpUUID"), e.getString("sessionId"), e.getString("nonce"), null,
            Instant.ofEpochSecond(e.getLong("now")));
        try {
            EidQr.verify(c.getString("jws"), exp);
            throw new AssertionError("test PKI accepted by the default trust");
        } catch (EidQrException x) {
            assertEquals(EidQrException.CHAIN_INVALID, x.code());
        }
    }

    /** The embedded 04 CA's SKI is the default allowed issuer. */
    @Test
    public void citizenIssuingCaSkiMatchesEmbedded04() {
        assertEquals(EidQr.CITIZEN_ISSUING_CA_SKI, Text.hex(EidChain.intermediates().get(2).subjectKeyId()));
    }

    /** exp far in the past must not wrap (exp + skew) × 1000 into the future (Go: QR_EXPIRED). */
    @Test
    public void farPastExpIsExpired() {
        Json.Obj v = (Json.Obj) Json.parse(Golden.resource("myqr_vectors.json"));
        String issuer = v.getString("issuer");
        Json.Obj ok = null;
        for (Object o : v.getArr("verify")) {
            Json.Obj c = (Json.Obj) o;
            if (c.getObj("expect").optNonEmpty("error") == null) {
                ok = c;
                break;
            }
        }
        if (ok == null) throw new AssertionError("no OK verify vector");
        Json.Obj e = ok.getObj("expect");
        EidQr.Expect exp = new EidQr.Expect(e.getString("rpUUID"), e.getString("sessionId"), e.getString("nonce"), issuer,
            Instant.ofEpochSecond(e.getLong("now")));
        String payload = new String(java.util.Base64.getUrlDecoder().decode(ok.getString("jws").split("\\.")[1]),
            java.nio.charset.StandardCharsets.UTF_8);
        Json.Obj claims = (Json.Obj) Json.parse(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        String etsi = claims.getString("sub");
        // The untouched claims pass; only iat/exp change below.
        EidQr.checkClaims(claims, exp, etsi, exp.now());
        long far = -15_000_000_000_000_000L;
        String bad = payload.replaceFirst("\"iat\":-?\\d+", "\"iat\":" + (far - 300)).replaceFirst("\"exp\":-?\\d+", "\"exp\":" + far);
        assertTrue(bad, bad.contains("\"exp\":" + far) && bad.contains("\"iat\":" + (far - 300)));
        try {
            EidQr.checkClaims((Json.Obj) Json.parse(bad.getBytes(java.nio.charset.StandardCharsets.UTF_8)), exp, etsi, exp.now());
            throw new AssertionError("far-past exp accepted");
        } catch (EidQrException x) {
            assertEquals(EidQrException.EXPIRED, x.code());
        }
    }
}
