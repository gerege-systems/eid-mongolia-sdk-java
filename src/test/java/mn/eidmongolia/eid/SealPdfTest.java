package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.KeyPair;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import mn.eidmongolia.eid.pades.CompleteOptions;
import mn.eidmongolia.eid.pades.EidPades;
import mn.eidmongolia.eid.pades.EidPadesException;
import mn.eidmongolia.eid.pades.SealOptions;
import mn.eidmongolia.eid.pades.Sealer;
import mn.eidmongolia.eid.pades.SignatureAppearance;
import org.junit.Test;

/**
 * EidPades.sealPdf (Go pades/seal.go SealPDF; seal_test.go TestSealPDF* error paths): certificate → prepare → seal the
 * DTBS → complete. The PAdES-LT output itself is the golden-tested {@link EidPades#complete}; here the flow, its checks
 * and its error passthrough are proven — the TSA is unreachable, so a correct seal ends in TSA_UNAVAILABLE right after
 * complete accepted the organisation's signature over the DTBS.
 */
public class SealPdfTest {
    static final String ORG = "NTRMN-0000000";
    static final TestCerts.Ca CA = new TestCerts.Ca("TEST ONLY Org Issuing CA");

    static byte[] pdf() {
        return TestRes.resource("golden/input/quartz-pdf13.pdf");
    }

    static Object[] sealCert(int ku) {
        KeyPair k = TestCerts.ec();
        TestCerts.Spec s = CA.issue(k).attr("2.5.4.6", "MN").attr("2.5.4.10", "TEST ONLY Golden Org LLC").cn("TEST ONLY Golden Org LLC")
            .attr("2.5.4.97", ORG);
        s.ku = ku;
        return new Object[] {k, TestCerts.cert(s)};
    }

    /** A fake organisation seal: certificate [cert], seals with [key] (the CA's NONEwithECDSA over the DTBS). */
    static final class FakeSealer implements Sealer {
        final byte[] cert;
        final byte[] sealCert;
        final KeyPair key;
        final List<byte[]> sealed = new ArrayList<>();
        RuntimeException certErr;
        RuntimeException sealErr;

        FakeSealer(byte[] cert, byte[] sealCert, KeyPair key) {
            this.cert = cert;
            this.sealCert = sealCert;
            this.key = key;
        }

        @Override
        public SealCertificate certificate(String orgEtsi) {
            if (certErr != null) throw certErr;
            return new SealCertificate(orgEtsi, cert, "1", "", "", Instant.EPOCH, Instant.EPOCH, "QUALIFIED");
        }

        @Override
        public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash) {
            if (sealErr != null) throw sealErr;
            assertEquals(HashAlgorithm.SHA_256, hash);
            assertEquals(32, digest.length);
            sealed.add(digest);
            return new SealResult(orgEtsi, SealServiceTest.signDigest(key, digest), "ecdsa-with-SHA256", sealCert, "QUALIFIED", Instant.EPOCH, "{}");
        }
    }

    static SealOptions opts() {
        return SealOptions.builder().invisible(true).chain(List.of(CA.der)).reason("Нэхэмжлэх")
            .complete(CompleteOptions.builder().tsaUrl("http://tsa.invalid/").transport((m, u, ct, b) -> {
                throw new IOException("offline");
            }).build()).build();
    }

    @Test
    public void sealsTheDtbsThenCompletes() {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        FakeSealer s = new FakeSealer((byte[]) c[1], (byte[]) c[1], (KeyPair) c[0]);
        try {
            EidPades.sealPdf(s, ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            // complete verified the seal over the DTBS (else SIGNATURE_INVALID) and reached the TSA.
            assertEquals("TSA_UNAVAILABLE", e.code());
            assertTrue(e.retryable());
        }
        assertEquals(1, s.sealed.size());
        // The default (visible seal stamp, golden v12) takes the same path: the stamp is prepared, sealed, completed.
        FakeSealer v = new FakeSealer((byte[]) c[1], (byte[]) c[1], (KeyPair) c[0]);
        try {
            EidPades.sealPdf(v, ORG, pdf(), SealOptions.builder().chain(List.of(CA.der)).complete(opts().complete()).build());
            fail();
        } catch (EidPadesException e) {
            assertEquals("TSA_UNAVAILABLE", e.code());
        }
        assertEquals(1, v.sealed.size());
        assertTrue(!java.util.Arrays.equals(s.sealed.get(0), v.sealed.get(0)));
    }

    @Test
    public void checks() {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        byte[] cert = (byte[]) c[1];
        KeyPair key = (KeyPair) c[0];
        // An explicit stamp rect outside the page → REQUEST_INVALID before the seal call (no automatic fallback).
        FakeSealer s = new FakeSealer(cert, cert, key);
        try {
            EidPades.sealPdf(s, ORG, pdf(), SealOptions.builder().chain(List.of(CA.der))
                .appearance(new SignatureAppearance(1, 10000, 10000, 220, 64, null, true)).build());
            fail();
        } catch (EidPadesException e) {
            assertEquals("REQUEST_INVALID", e.code());
        }
        assertTrue(s.sealed.isEmpty());
        try {
            EidPades.sealPdf(null, ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            assertEquals("REQUEST_INVALID", e.code());
        }
        // Not an e-Seal certificate (digitalSignature set) → SIGNER_INVALID, nothing sealed.
        Object[] sign = sealCert(TestCerts.KU_NON_REPUDIATION | TestCerts.KU_DIGITAL_SIGNATURE);
        FakeSealer ns = new FakeSealer((byte[]) sign[1], (byte[]) sign[1], (KeyPair) sign[0]);
        try {
            EidPades.sealPdf(ns, ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            assertEquals("SIGNER_INVALID", e.code());
        }
        assertTrue(ns.sealed.isEmpty());
        // The certificate changed between the two calls → SIGNER_INVALID.
        Object[] other = sealCert(TestCerts.KU_NON_REPUDIATION);
        FakeSealer ch = new FakeSealer(cert, (byte[]) other[1], (KeyPair) other[0]);
        try {
            EidPades.sealPdf(ch, ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            assertEquals("SIGNER_INVALID", e.code());
        }
        // The sealer's errors pass through unchanged (403, 503 SEAL_SERVICE_DISABLED, 409 …).
        FakeSealer dis = new FakeSealer(cert, cert, key);
        dis.sealErr = new EidException.SealServiceDisabled(503, "SEAL_SERVICE_DISABLED", "off", "{}", "sealing", java.time.Duration.ZERO, null);
        try {
            EidPades.sealPdf(dis, ORG, pdf(), opts());
            fail();
        } catch (EidException.SealServiceDisabled e) {
            assertEquals("sealing", e.service());
        }
        // A wrong signature from the sealer → SIGNATURE_INVALID (complete checks it before the TSA).
        FakeSealer wrong = new FakeSealer(cert, cert, TestCerts.ec());
        try {
            EidPades.sealPdf(wrong, ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            assertEquals("SIGNATURE_INVALID", e.code());
        }
    }

    /** SealService is the Sealer: the full chain through the fake RP-API (GET certificate, POST /seal/{org}). */
    @Test
    public void sealServiceIsTheSealer() {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        byte[] cert = (byte[]) c[1];
        String b64 = java.util.Base64.getEncoder().encodeToString(cert);
        FakeRp seal = SealServiceTest.sealReply((KeyPair) c[0], cert);
        java.util.function.Function<EidHttpRequest, EidHttpResponse> sealH = seal.handler;
        FakeRp rp = new FakeRp(q -> q.method().equals("GET")
            ? FakeRp.json(200, "{\"orgEtsi\":\"" + ORG + "\",\"certificate\":\"" + b64 + "\"}") : sealH.apply(q));
        try {
            EidPades.sealPdf(rp.client().seal(), ORG, pdf(), opts());
            fail();
        } catch (EidPadesException e) {
            assertEquals("TSA_UNAVAILABLE", e.code());
        }
        assertEquals(2, rp.seen.size());
        FakeRp.assertRequest(rp.seen.get(0), "GET", "/seal/certificate/" + ORG);
        FakeRp.assertRequest(rp.seen.get(1), "POST", "/seal/" + ORG);
    }
}
