package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import mn.eidmongolia.eid.pades.Registration;
import mn.eidmongolia.eid.pades.SealRegistration;
import org.junit.Test;

/**
 * POST /seal/{orgEtsi}/registrations and the seal reservation (CA V158) — port of Go sealregister_test.go
 * (TestRegisterSealedPDF, …Validate, …Errors, …PriorMismatch, TestSealRegisterErrorCodes, TestSealForDocument).
 */
public class SealRegisterTest {
    static final String ORG = "NTRMN-6235972";
    static final String DOC = "3f0c2a8e-6b1d-4c55-9a77-000000000002";
    /** CA dto.SealRegisterRequest members (DisallowUnknownFields). */
    static final Set<String> CA_FIELDS = Set.of("docID", "revIndex", "cms", "fileName", "inSha256", "sigRevSha256", "outSha256",
        "priorCmsSha256", "priorRevisionSha256");
    static final String REGISTERED = "{\"docID\":\"" + DOC + "\",\"revIndex\":1,\"registeredAt\":\"2026-11-25T12:00:00+08:00\","
        + "\"verifyUrl\":\"https://ca.eidmongolia.mn/verify/" + DOC + "\"}";

    static String h64(char c) {
        return String.valueOf(c).repeat(64);
    }

    static SealRegistration reg(String docId, int rev, String cms, String fileName, String in, String sigRev, String out,
        List<String> priorCms, List<String> priorRev, List<Registration.PriorSignature> prior) {
        return new SealRegistration(docId, rev, cms, fileName, in, sigRev, out, priorCms, priorRev, prior);
    }

    static SealRegistration base() {
        return reg(DOC, 1, "MAE=", "Нэхэмжлэх.pdf", h64('a'), h64('b'), h64('c'), null, null, null);
    }

    /** The CA decodes with DisallowUnknownFields: an unknown member → 400 REQUEST_INVALID. */
    static FakeRp ca(int[] status) {
        return new FakeRp(q -> {
            Json.Obj b = (Json.Obj) Json.parse(q.body());
            if (!CA_FIELDS.containsAll(b.keySet())) return FakeRp.json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}");
            return FakeRp.json(status[0], REGISTERED);
        });
    }

    @Test
    public void registerSealedPdf() {
        int[] status = {201};
        FakeRp rp = ca(status);
        PdfSignatureRegistered out = rp.client().seal().registerSealedPdf(" " + ORG + " ", base());
        FakeRp.assertRequest(rp.last(), "POST", "/seal/" + ORG + "/registrations");
        assertEquals("Bearer " + FakeRp.CREDS.apiSecret(), rp.last().headers().get("Authorization"));
        assertEquals(Duration.ofSeconds(80), rp.last().timeout());
        FakeRp.assertJsonEquals("body", "{\"docID\":\"" + DOC + "\",\"revIndex\":1,\"cms\":\"MAE=\",\"fileName\":\"Нэхэмжлэх.pdf\","
            + "\"inSha256\":\"" + h64('a') + "\",\"sigRevSha256\":\"" + h64('b') + "\",\"outSha256\":\"" + h64('c') + "\"}", rp.lastBody());
        for (String k : new String[] {"medium", "sessionID", "pageSha256", "onBehalfOf", "signerEtsi", "priorCmsSha256", "priorSignatures"}) {
            assertFalse(k, rp.lastBody().contains("\"" + k + "\""));
        }
        assertTrue(out.created());
        assertEquals(DOC, out.docId());
        assertEquals(1, out.revIndex());
        assertFalse(out.verifyUrl().isEmpty());
        assertFalse(out.registeredAt().isEmpty());
        // fileName is optional — not sent when empty; 200 = idempotent repeat.
        status[0] = 200;
        out = rp.client().seal().registerSealedPdf(ORG, reg(DOC, 1, "MAE=", "  ", h64('a'), h64('b'), h64('c'), null, null, null));
        assertFalse(out.created());
        assertFalse(rp.lastBody(), rp.lastBody().contains("fileName"));
        // pdfTimeout applies.
        rp.builder().pdfTimeout(Duration.ofMillis(50)).build().seal().registerSealedPdf(ORG, base());
        assertEquals(Duration.ofMillis(50), rp.last().timeout());
    }

    @Test
    public void validateBeforeSending() {
        FakeRp rp = FakeRp.reply(201, REGISTERED);
        SealService s = rp.client().seal();
        String bigCms = Base64.getEncoder().encodeToString(new byte[28673]);
        Map<String, UnaryOperator<SealRegistration>> bad = new LinkedHashMap<>();
        SealRegistration b = base();
        bad.put("docID", r -> reg(DOC.toUpperCase(), 1, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("revIndex 0", r -> reg(DOC, 0, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("revIndex 17", r -> reg(DOC, 17, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("prior count", r -> reg(DOC, 1, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), List.of(h64('d')), null, null));
        bad.put("prior missing", r -> reg(DOC, 2, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("prior hex", r -> reg(DOC, 2, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, List.of("x"), null));
        bad.put("out", r -> reg(DOC, 1, r.cms(), r.fileName(), r.inSha256(), r.sigRevSha256(), "x", null, null, null));
        bad.put("in upper case", r -> reg(DOC, 1, r.cms(), r.fileName(), h64('A'), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("sigRev", r -> reg(DOC, 1, r.cms(), r.fileName(), r.inSha256(), "", r.outSha256(), null, null, null));
        bad.put("fileName", r -> reg(DOC, 1, r.cms(), "а".repeat(121), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("cms empty", r -> reg(DOC, 1, "", r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("cms not base64", r -> reg(DOC, 1, "MAE", r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("cms too large", r -> reg(DOC, 1, bigCms, r.fileName(), r.inSha256(), r.sigRevSha256(), r.outSha256(), null, null, null));
        bad.put("null", r -> null);
        for (Map.Entry<String, UnaryOperator<SealRegistration>> e : bad.entrySet()) {
            try {
                s.registerSealedPdf(ORG, e.getValue().apply(b));
                fail(e.getKey());
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        for (String org : new String[] {"", "PNOMN-1", "NTRMN-", "NTRMN-ab_c", null}) {
            try {
                s.registerSealedPdf(org, b);
                fail("orgEtsi " + org);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals("no request for a shape error", 0, rp.seen.size());
        // Bounds: 120 characters, 28 672 bytes, prior revision + CMS mixed.
        reg(DOC, 3, Base64.getEncoder().encodeToString(new byte[28672]), "а".repeat(120), h64('a'), h64('b'), h64('c'), List.of(h64('d')),
            List.of(h64('e')), null).validate();
    }

    @Test
    public void errorCodes() {
        assertEquals(List.of("REQUEST_TOO_LARGE", "REQUEST_INVALID", "RATE_LIMITED", "STATE_UNAVAILABLE", "CMS_INVALID", "SIGNER_MISMATCH",
            "SIGNER_CERT_INVALID", "SIGNATURE_INVALID", "SEAL_NOT_FOUND", "SEAL_DOC_MISMATCH", "TIMESTAMP_INVALID", "DOC_ID_RESERVED",
            "DOC_ID_CONFLICT", "PRIOR_MISMATCH", "REGISTRY_CONFLICT"), EidErrorCodes.SEAL_REGISTER);
        Map<String, Integer> status = Map.ofEntries(Map.entry("REQUEST_TOO_LARGE", 413), Map.entry("REQUEST_INVALID", 400),
            Map.entry("RATE_LIMITED", 429), Map.entry("STATE_UNAVAILABLE", 503), Map.entry("CMS_INVALID", 400), Map.entry("SIGNER_MISMATCH", 409),
            Map.entry("SIGNER_CERT_INVALID", 409), Map.entry("SIGNATURE_INVALID", 400), Map.entry("SEAL_NOT_FOUND", 409),
            Map.entry("SEAL_DOC_MISMATCH", 409), Map.entry("TIMESTAMP_INVALID", 400), Map.entry("DOC_ID_RESERVED", 409),
            Map.entry("DOC_ID_CONFLICT", 409), Map.entry("PRIOR_MISMATCH", 409), Map.entry("REGISTRY_CONFLICT", 409));
        assertEquals(EidErrorCodes.SEAL_REGISTER.size(), status.size());
        for (String code : EidErrorCodes.SEAL_REGISTER) {
            int st = status.get(code);
            FakeRp rp = new FakeRp(q -> new EidHttpResponse(st, st == 429 || st == 503
                ? Map.of("Content-Type", List.of("application/json"), "Retry-After", List.of("600"))
                : Map.of("Content-Type", List.of("application/json")), EidCrypto.utf8("{\"error\":\"x\",\"code\":\"" + code + "\"}")));
            try {
                rp.client().seal().registerSealedPdf(ORG, base());
                fail(code);
            } catch (EidException.Api e) {
                assertEquals(code, e.code());
                assertEquals(code, st, e.status());
                boolean retry = st == 429 || st == 503;
                assertEquals(code, retry, e.retryable());
                if (retry) assertEquals(Duration.ofSeconds(600), e.retryAfter());
                if (code.equals("SEAL_NOT_FOUND")) assertTrue(e instanceof EidException.SealNotFound);
                if (code.equals("SEAL_DOC_MISMATCH")) assertTrue(e instanceof EidException.SealDocMismatch);
                if (code.equals("DOC_ID_RESERVED")) assertTrue(e instanceof EidException.DocIdReserved);
            }
        }
        try {
            FakeRp.reply(403, "{\"error\":\"SEAL эрхгүй\"}").client().seal().registerSealedPdf(ORG, base());
            fail("403");
        } catch (EidException.Forbidden expected) {
            // ok
        }
        try {
            FakeRp.reply(501, "{\"error\":\"тамганы бүртгэл тохируулаагүй\"}").client().seal().registerSealedPdf(ORG, base());
            fail("501");
        } catch (EidException.Api e) {
            assertEquals(501, e.status());
        }
    }

    /** Go try(): the CA accepts only the wanted split; every other body → 409 [code]. Returns {calls, created(0/1)}. */
    static int[] attempt(SealRegistration r, String wantCms, String wantRev, String code, EidException[] err) {
        int[] calls = {0, 0};
        FakeRp rp = new FakeRp(q -> {
            calls[0]++;
            Json.Obj b = (Json.Obj) Json.parse(q.body());
            if (!CA_FIELDS.containsAll(b.keySet())) return FakeRp.json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}");
            if (join(b.optArr("priorCmsSha256")).equals(wantCms) && join(b.optArr("priorRevisionSha256")).equals(wantRev)) {
                return FakeRp.json(201, REGISTERED);
            }
            return FakeRp.json(409, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
        });
        try {
            calls[1] = rp.client().seal().registerSealedPdf(ORG, r).created() ? 1 : 0;
        } catch (EidException e) {
            err[0] = e;
        }
        return calls;
    }

    static String join(List<Object> a) {
        List<String> s = new ArrayList<>();
        if (a != null) for (Object o : a) s.add((String) o);
        return String.join(",", s);
    }

    @Test
    public void priorMismatchRetry() {
        List<Registration.PriorSignature> prior = List.of(new Registration.PriorSignature(h64('1'), h64('3')),
            new Registration.PriorSignature(h64('2'), h64('4')));
        SealRegistration r = reg(DOC, 3, "MAE=", null, h64('a'), h64('b'), h64('c'), List.of(h64('1'), h64('2')), null, prior);
        EidException[] err = {null};
        int[] n = attempt(r, h64('2'), h64('3'), "PRIOR_MISMATCH", err);
        assertEquals("first row mode A", 2, n[0]);
        assertEquals(1, n[1]);
        err[0] = null;
        n = attempt(r, "-", "-", "PRIOR_MISMATCH", err);
        assertEquals(4, n[0]);
        assertEquals("PRIOR_MISMATCH", err[0].code());
        err[0] = null;
        n = attempt(r, "-", "-", "SEAL_NOT_FOUND", err);
        assertEquals(1, n[0]);
        assertTrue(err[0] instanceof EidException.SealNotFound);
        err[0] = null;
        SealRegistration manual = reg(DOC, 3, "MAE=", null, h64('a'), h64('b'), h64('c'), List.of(h64('2')), List.of(h64('3')), prior);
        n = attempt(manual, "-", "-", "PRIOR_MISMATCH", err);
        assertEquals("manual split is not retried", 1, n[0]);
        assertEquals("PRIOR_MISMATCH", err[0].code());
    }

    @Test
    public void sealForDocument() {
        Object[] c = SealServiceTest.sealCert(TestCerts.KU_NON_REPUDIATION);
        FakeRp rp = SealServiceTest.sealReply((KeyPair) c[0], (byte[]) c[1]);
        SealService s = rp.client().seal();
        byte[] d = SealServiceTest.sha256("dtbs");
        s.sealForDocument(ORG, d, DOC, 2);
        FakeRp.assertRequest(rp.last(), "POST", "/seal/" + ORG);
        FakeRp.assertJsonEquals("body", "{\"digest\":\"" + Base64.getEncoder().encodeToString(d) + "\",\"hashType\":\"SHA256\",\"docId\":\"" + DOC
            + "\",\"revIndex\":2}", rp.lastBody());
        s.seal(ORG, d, HashAlgorithm.SHA_256);
        assertFalse(rp.lastBody(), rp.lastBody().contains("docId") || rp.lastBody().contains("revIndex"));
        int n = rp.seen.size();
        Object[][] bad = {{DOC.toUpperCase(), 1, d}, {DOC, 0, d}, {DOC, 17, d}, {"", 2, d}, {null, 2, d}, {DOC, 1, new byte[48]}};
        for (Object[] b : bad) {
            try {
                s.sealForDocument(ORG, (byte[]) b[2], (String) b[0], (Integer) b[1]);
                fail(b[0] + "/" + b[1]);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals("bad reservation never sent", n, rp.seen.size());
    }
}
