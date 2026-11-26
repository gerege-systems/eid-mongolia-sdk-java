package mn.eidmongolia.eid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import mn.eidmongolia.eid.pades.Medium;
import mn.eidmongolia.eid.pades.Registration;
import org.junit.Test;

/** PdfService.registerSignature: preflight checks, PRIOR_MISMATCH retries, timeout (port of Go pdfregister_test.go). */
public class PdfServiceTest {
    /** CA dto.PDFSignatureRegisterRequest member names (the CA decodes with DisallowUnknownFields). */
    static final Set<String> CA_FIELDS = Set.of("docID", "revIndex", "medium", "sessionID", "cms", "fileName", "inSha256",
        "pageSha256", "sigRevSha256", "outSha256", "priorCmsSha256", "priorRevisionSha256", "onBehalfOf", "signerEtsi");

    static Registration reg(int revIndex, Medium medium, String session, String page, List<String> priorCms,
        List<String> priorRev, List<Registration.PriorSignature> prior) {
        return new Registration("d", revIndex, medium, session, "MAE=", "a.pdf", "in", page, "sr", "out", priorCms, priorRev, null,
            null, prior);
    }

    // Go TestRegisterSignature (preflight)
    @Test
    public void preflight() {
        FakeRp rp = FakeRp.reply(201, "{}");
        PdfService p = rp.client().pdf();
        Registration ok = reg(1, Medium.PHONE, "s", "pg", null, null, null);
        Registration[] bad = {
            null,
            new Registration("", 1, Medium.PHONE, "s", "MAE=", "a.pdf", "in", "pg", "sr", "out", null, null, null, null, null),
            new Registration("d", 0, Medium.PHONE, "s", "MAE=", "a.pdf", "in", "pg", "sr", "out", null, null, null, null, null),
            new Registration("d", 1, Medium.PHONE, "s", "", "a.pdf", "in", "pg", "sr", "out", null, null, null, null, null),
            reg(1, null, "s", "pg", null, null, null),
            reg(1, Medium.PHONE, "", "pg", null, null, null),
            reg(1, Medium.PHONE, "s", "", null, null, null),
        };
        for (Registration r : bad) {
            try {
                p.registerSignature(r);
                fail("алдаа хүлээв: " + r);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals(0, rp.seen.size());
        p.registerSignature(ok);
        assertEquals(1, rp.seen.size());
        assertEquals(Duration.ofSeconds(80), rp.last().timeout());
        assertTrue(CA_FIELDS.containsAll(rp.lastJson().keySet()));
        assertFalse("hasPage is never sent", rp.lastBody().contains("hasPage"));
        // token without session is fine; revIndex > 1 without page is fine
        p.registerSignature(reg(2, Medium.TOKEN, null, null, List.of("c1"), null, null));
        assertEquals(2, rp.seen.size());
    }

    // Go TestPDFTimeoutConfigurable
    @Test
    public void pdfTimeoutConfigurable() {
        FakeRp rp = FakeRp.reply(201, "{}");
        rp.builder().pdfTimeout(Duration.ofMillis(50)).build().pdf().registerSignature(reg(2, Medium.TOKEN, null, null, null, null, null));
        assertEquals(Duration.ofMillis(50), rp.last().timeout());
    }

    /** Go TestRegisterSignatureReplayAndPriorMismatch {@code try}: the CA accepts only the wanted split. */
    static int[] attempt(Registration r, String wantCms, String wantRev, String code, PdfSignatureRegistered[] out, EidException[] err) {
        int[] calls = {0};
        FakeRp rp = new FakeRp(q -> {
            calls[0]++;
            Json.Obj b = (Json.Obj) Json.parse(q.body());
            if (!CA_FIELDS.containsAll(b.keySet())) return FakeRp.json(400, "{\"error\":\"bad\",\"code\":\"REQUEST_INVALID\"}");
            if (join(b.optArr("priorCmsSha256")).equals(wantCms) && join(b.optArr("priorRevisionSha256")).equals(wantRev)) {
                return FakeRp.json(201, "{\"docID\":\"d\",\"revIndex\":3,\"registeredAt\":\"x\",\"verifyUrl\":\"v\"}");
            }
            return FakeRp.json(409, "{\"error\":\"x\",\"code\":\"" + code + "\"}");
        });
        try {
            out[0] = rp.client().pdf().registerSignature(r);
        } catch (EidException e) {
            err[0] = e;
        }
        return calls;
    }

    private static String join(List<Object> a) {
        if (a == null) return "";
        List<String> s = new ArrayList<>();
        for (Object o : a) s.add((String) o);
        return String.join(",", s);
    }

    // Go TestRegisterSignatureReplayAndPriorMismatch
    @Test
    public void priorMismatchRetries() {
        List<Registration.PriorSignature> prior = List.of(new Registration.PriorSignature("c1", "v1"), new Registration.PriorSignature("c2", "v2"));
        Registration r3 = reg(3, Medium.TOKEN, null, null, List.of("c1", "c2"), null, prior);
        PdfSignatureRegistered[] out = new PdfSignatureRegistered[1];
        EidException[] err = new EidException[1];

        int[] n = attempt(r3, "c2", "v1", "PRIOR_MISMATCH", out, err);
        assertEquals("first prior by revision", 2, n[0]);
        assertTrue(out[0].created());

        out[0] = null;
        n = attempt(r3, "c1", "v2", "PRIOR_MISMATCH", out, err);
        assertEquals("second prior by revision (all combinations)", 4, n[0]);
        assertEquals(3, out[0].revIndex());

        n = attempt(r3, "-", "-", "PRIOR_MISMATCH", out, err);
        assertEquals(4, n[0]);
        assertEquals("PRIOR_MISMATCH", err[0].code());
        assertTrue(err[0] instanceof EidException.Api);

        err[0] = null;
        n = attempt(r3, "-", "-", "REGISTRY_CONFLICT", out, err);
        assertEquals("another error: no retry", 1, n[0]);
        assertEquals("REGISTRY_CONFLICT", err[0].code());

        // manually split → no retries
        Registration manual = reg(3, Medium.TOKEN, null, null, List.of("c2"), List.of("v2"), prior);
        err[0] = null;
        n = attempt(manual, "-", "-", "PRIOR_MISMATCH", out, err);
        assertEquals(1, n[0]);
        assertEquals("PRIOR_MISMATCH", err[0].code());

        // priorSignatures not covering revIndex − 1 → no retries
        err[0] = null;
        n = attempt(reg(4, Medium.TOKEN, null, null, List.of("c1", "c2", "c3"), null, prior), "-", "-", "PRIOR_MISMATCH", out, err);
        assertEquals(1, n[0]);
    }

    // Go TestPriorSplits
    @Test
    public void priorSplits() {
        List<boolean[]> got = PdfService.priorSplits(2);
        assertEquals(3, got.size());
        assertArrayEquals(new boolean[] {true, false}, got.get(0));
        assertArrayEquals(new boolean[] {true, true}, got.get(1));
        assertArrayEquals(new boolean[] {false, true}, got.get(2));
        assertEquals("n > 4: only the leading k", 6, PdfService.priorSplits(6).size());
        assertEquals("n = 4: 2^4 − 1", 15, PdfService.priorSplits(4).size());
    }

    // Go TestPDFRegisterErrorCodes
    @Test
    public void errorCodes() {
        assertEquals(List.of("REQUEST_INVALID", "REQUEST_TOO_LARGE", "CMS_INVALID", "SIGNATURE_INVALID", "TIMESTAMP_INVALID",
            "SIGNER_MISMATCH", "SIGNER_CERT_INVALID", "TOKEN_CERT_INVALID", "TOKEN_ORG_MISMATCH", "SESSION_MISMATCH",
            "SESSION_NOT_COMPLETE", "SESSION_FAILED", "CLAIMED_ROLE_MISMATCH", "REPRESENTATION_REVOKED", "DOC_ID_CONFLICT",
            "REGISTRY_CONFLICT", "DOC_NOT_FOUND", "PRIOR_MISMATCH", "RATE_LIMITED", "STATE_UNAVAILABLE"), EidErrorCodes.PDF_REGISTER);
    }
}
