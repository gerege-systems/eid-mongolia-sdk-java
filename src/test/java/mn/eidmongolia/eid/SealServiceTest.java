package mn.eidmongolia.eid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Test;

/**
 * SealService: seal a digest, certificate get / request / wait, seal grants request / status / wait (ports of Go
 * seal_test.go and seal_grant_test.go; TS seal.test.ts, seal-grant.test.ts).
 */
public class SealServiceTest {
    static final String ORG = "NTRMN-6235972";
    static final String REQ_ID = "5f0c2b1e-7a40-4c11-9a51-2f6e0d3c9b11";
    /** CA dto.SealRequest members (DisallowUnknownFields; CA V158 added docId / revIndex). */
    static final Set<String> CA_SEAL_FIELDS = Set.of("relyingPartyUUID", "relyingPartyName", "digest", "hashType", "docId", "revIndex");

    /** Go {@code sealTestCert}: EC P-256 self-signed with the given KeyUsage. */
    static Object[] sealCert(int ku) {
        KeyPair k = TestCerts.ec();
        TestCerts.Spec s = new TestCerts.Spec().attr("2.5.4.10", "TEST ONLY Golden Org LLC").cn("TEST ONLY Golden Org LLC");
        s.key = k;
        s.ku = ku;
        s.serial = 4242;
        return new Object[] {k, TestCerts.cert(s)};
    }

    static byte[] sha256(String s) {
        return EidCrypto.digest("SHA-256", s.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] signDigest(KeyPair k, byte[] digest) {
        try {
            Signature s = Signature.getInstance("NONEwithECDSA");
            s.initSign(k.getPrivate());
            s.update(digest);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Go {@code sealReply}: decodes the request (unknown member → 400) and seals with [key]. */
    static FakeRp sealReply(KeyPair key, byte[] certDer) {
        return new FakeRp(q -> {
            Json.Obj b = (Json.Obj) Json.parse(q.body());
            if (!CA_SEAL_FIELDS.containsAll(b.keySet())) return FakeRp.json(400, "{\"code\":\"REQUEST_INVALID\"}");
            byte[] digest = Base64.getDecoder().decode(b.optString("digest"));
            String sig = Base64.getEncoder().encodeToString(signDigest(key, digest));
            return FakeRp.json(200, "{\"orgEtsi\":\"" + ORG + "\",\"signature\":{\"value\":\"" + sig + "\",\"signatureAlgorithm\":\"ecdsa-with-SHA256\"},"
                + "\"cert\":{\"value\":\"" + Base64.getEncoder().encodeToString(certDer) + "\",\"certificateLevel\":\"QUALIFIED\"},\"sealedAt\":\"2026-11-09T04:05:06Z\"}");
        });
    }

    // Go TestSeal_RequestAndVerify
    @Test
    public void sealRequestAndVerify() throws Exception {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        KeyPair key = (KeyPair) c[0];
        byte[] der = (byte[]) c[1];
        FakeRp rp = sealReply(key, der);
        byte[] d = sha256("doc");
        SealResult r = rp.client().seal().seal(ORG, d, null);
        FakeRp.assertRequest(rp.last(), "POST", "/seal/" + ORG);
        assertEquals("Bearer " + FakeRp.CREDS.apiSecret(), rp.last().headers().get("Authorization"));
        FakeRp.assertJsonEquals("body", "{\"digest\":\"" + Base64.getEncoder().encodeToString(d) + "\",\"hashType\":\"SHA256\"}", rp.lastBody());
        assertEquals(ORG, r.orgEtsi());
        assertArrayEquals(der, r.certificate());
        assertEquals("QUALIFIED", r.certificateLevel());
        assertEquals("ecdsa-with-SHA256", r.signatureAlgorithm());
        assertEquals(Instant.parse("2026-11-09T04:05:06Z"), r.sealedAt());
        assertFalse(r.rawJson().isEmpty());
        Signature v = Signature.getInstance("NONEwithECDSA");
        v.initVerify(key.getPublic());
        v.update(d);
        assertTrue(v.verify(r.signature()));
    }

    // Go TestSeal_HashTypes (+ the CA V158 docId / revIndex members)
    @Test
    public void hashTypesAndDocRef() {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        FakeRp rp = sealReply((KeyPair) c[0], (byte[]) c[1]);
        SealService s = rp.client().seal();
        s.seal(ORG, new byte[48], HashAlgorithm.SHA_384);
        assertTrue(rp.lastBody(), rp.lastBody().contains("\"hashType\":\"SHA384\""));
        s.seal(ORG, new byte[64], HashAlgorithm.SHA_512);
        assertTrue(rp.lastBody(), rp.lastBody().contains("\"hashType\":\"SHA512\""));
        int n = rp.seen.size();
        try {
            s.seal(ORG, new byte[32], HashAlgorithm.SHA_384);
            fail("length mismatch accepted");
        } catch (IllegalArgumentException expected) {
            assertEquals("no request", n, rp.seen.size());
        }
        s.seal(ORG, new byte[32], HashAlgorithm.SHA_256, "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", 2);
        FakeRp.assertJsonEquals("docId body", "{\"digest\":\"" + Base64.getEncoder().encodeToString(new byte[32])
            + "\",\"hashType\":\"SHA256\",\"docId\":\"6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f\",\"revIndex\":2}", rp.lastBody());
        assertTrue(CA_SEAL_FIELDS.containsAll(rp.lastJson().keySet()));
        n = rp.seen.size();
        String[][] bad = {{"6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", "0"}, {"", "1"}, {"6F0C2B9E-3A1D-4C55-9B7E-0A1B2C3D4E5F", "1"},
            {"6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", "-1"}};
        for (String[] b : bad) {
            try {
                s.seal(ORG, new byte[32], null, b[0], Integer.parseInt(b[1]));
                fail(b[0] + "/" + b[1]);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals(n, rp.seen.size());
    }

    // Go TestSeal_Rejects
    @Test
    public void sealRejects() {
        byte[] d = sha256("doc");
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        try {
            sealReply(TestCerts.ec(), (byte[]) c[1]).client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
            fail("wrong key");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.SEAL_SIGNATURE, e.reason());
        }
        Object[] sign = sealCert(TestCerts.KU_NON_REPUDIATION | TestCerts.KU_DIGITAL_SIGNATURE);
        try {
            sealReply((KeyPair) sign[0], (byte[]) sign[1]).client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
            fail("non-seal cert");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.SEAL_NOT_ESEAL, e.reason());
        }
        try {
            FakeRp.reply(200, "{\"orgEtsi\":\"" + ORG + "\",\"signature\":null,\"cert\":null}").client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
            fail("empty");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.SEAL_RESPONSE, e.reason());
        }
        try {
            FakeRp.reply(403, "{\"code\":\"FORBIDDEN\",\"error\":\"SEAL permission алга\"}").client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
            fail("403");
        } catch (EidException.Forbidden expected) {
            // ok
        }
        FakeRp rl = new FakeRp(q -> new EidHttpResponse(429, Map.of("Retry-After", List.of("7")),
            "{\"code\":\"RATE_LIMITED\",\"error\":\"хэт олон\"}".getBytes(StandardCharsets.UTF_8)));
        try {
            rl.client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
            fail("429");
        } catch (EidException.Api e) {
            assertTrue(e.retryable());
            assertEquals(Duration.ofSeconds(7), e.retryAfter());
        }
    }

    // Go TestSeal_Certificate + TestIsSealCertificate
    @Test
    public void certificateAndIsSeal() {
        byte[] der = (byte[]) sealCert(TestCerts.KU_NON_REPUDIATION)[1];
        FakeRp rp = FakeRp.reply(200, "{\"orgEtsi\":\"" + ORG + "\",\"certificate\":\"" + Base64.getEncoder().encodeToString(der) + "\",\"serialNumber\":\"4242\","
            + "\"subjectDn\":\"CN=Gerege Systems LLC\",\"issuerDn\":\"CN=x\",\"notBefore\":\"2026-11-01T00:00:00Z\",\"notAfter\":\"2029-11-01T00:00:00Z\","
            + "\"certificateLevel\":\"QUALIFIED\"}");
        SealCertificate sc = rp.client().seal().certificate(ORG);
        FakeRp.assertRequest(rp.last(), "GET", "/seal/certificate/" + ORG);
        assertArrayEquals(der, sc.certificate());
        assertEquals("4242", sc.serialNumber());
        assertEquals(Instant.parse("2029-11-01T00:00:00Z"), sc.notAfter());
        try {
            FakeRp.reply(200, "{\"orgEtsi\":\"" + ORG + "\"}").client().seal().certificate(ORG);
            fail("empty certificate");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.SEAL_RESPONSE, e.reason());
        }
        byte[] sign = (byte[]) sealCert(TestCerts.KU_NON_REPUDIATION | TestCerts.KU_DIGITAL_SIGNATURE)[1];
        assertTrue(SealService.isSealCertificate(der));
        assertFalse(SealService.isSealCertificate(sign));
        assertFalse(SealService.isSealCertificate((byte[]) null));
        assertFalse(SealService.isSealCertificate((java.security.cert.X509Certificate) null));
        // EKU present → not a seal certificate; a CA → not.
        KeyPair k = TestCerts.ec();
        TestCerts.Spec e = new TestCerts.Spec().cn("TEST ONLY x");
        e.key = k;
        e.ku = TestCerts.KU_NON_REPUDIATION;
        e.eku = List.of(TestCerts.EKU_EMAIL);
        assertFalse(SealService.isSealCertificate(TestCerts.cert(e)));
        e.eku = null;
        e.ca = true;
        assertFalse(SealService.isSealCertificate(TestCerts.cert(e)));
    }

    static String reqBody(String status, String extra) {
        return "{\"requestId\":\"" + REQ_ID + "\",\"orgEtsi\":\"" + ORG + "\",\"status\":\"" + status
            + "\",\"createdAt\":\"2026-11-09T05:00:00Z\",\"expiresAt\":\"2026-11-09T05:07:00Z\"" + extra + "}";
    }

    static String issuedBody(byte[] der) {
        return reqBody("ISSUED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\",\"certificate\":{\"orgEtsi\":\"" + ORG + "\",\"certificate\":\""
            + Base64.getEncoder().encodeToString(der) + "\",\"serialNumber\":\"88002\",\"notBefore\":\"2026-11-09T05:01:00Z\","
            + "\"notAfter\":\"2029-11-09T05:01:00Z\",\"certificateLevel\":\"QUALIFIED\"}");
    }

    /** Go {@code sealSeq}: answers in order (the last one repeats). */
    static FakeRp seq(EidHttpResponse... steps) {
        int[] i = {0};
        return new FakeRp(q -> steps[Math.min(i[0]++, steps.length - 1)]);
    }

    static EidHttpResponse retryAfter(int status, String body, String ra) {
        return new EidHttpResponse(status, Map.of("Content-Type", List.of("application/json"), "Retry-After", List.of(ra)),
            body.getBytes(StandardCharsets.UTF_8));
    }

    /** A client whose sleeps only move the fake clock (recorded). */
    static EidClient waiting(FakeRp rp, List<Duration> sleeps) {
        return rp.builder().sleeper(d -> {
            sleeps.add(d);
            rp.clock.advance(d);
        }).build();
    }

    // Go TestSeal_RequestCertificate + TestSeal_CertificateRequestIssued
    @Test
    public void requestCertificate() {
        FakeRp rp = FakeRp.reply(202, reqBody("PENDING", ",\"approvers\":2"));
        SealCertificateRequest r = rp.client().seal().requestCertificate(ORG);
        FakeRp.assertRequest(rp.last(), "POST", "/seal/certificate/" + ORG);
        assertEquals("{}", rp.lastBody());
        assertEquals(REQ_ID, r.requestId());
        assertEquals(SealCertificateRequest.STATUS_PENDING, r.status());
        assertEquals(2, r.approvers());
        assertEquals(Instant.parse("2026-11-09T05:07:00Z"), r.expiresAt());
        assertNull(r.certificate());

        byte[] der = (byte[]) sealCert(TestCerts.KU_NON_REPUDIATION)[1];
        FakeRp iss = FakeRp.reply(200, issuedBody(der));
        SealCertificateRequest i = iss.client().seal().certificateRequest(ORG, REQ_ID);
        FakeRp.assertRequest(iss.last(), "GET", "/seal/certificate/" + ORG + "/requests/" + REQ_ID);
        assertEquals(SealCertificateRequest.STATUS_ISSUED, i.status());
        assertArrayEquals(der, i.certificate().certificate());
        assertEquals("88002", i.certificate().serialNumber());
        for (String body : new String[] {reqBody("ISSUED", ""), "{\"status\":\"PENDING\"}"}) {
            try {
                FakeRp.reply(200, body).client().seal().certificateRequest(ORG, REQ_ID);
                fail(body);
            } catch (EidException.Validation e) {
                assertEquals(ValidationReasons.SEAL_RESPONSE, e.reason());
            }
        }
    }

    // Go TestSeal_WaitForCertificate, …Terminal, …TimeoutAndCancel, …RetryAfter
    @Test
    public void waitForCertificate() {
        byte[] der = (byte[]) sealCert(TestCerts.KU_NON_REPUDIATION)[1];
        FakeRp rp = seq(FakeRp.json(200, reqBody("PENDING", "")), FakeRp.json(200, reqBody("APPROVED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\"")),
            FakeRp.json(200, issuedBody(der)));
        List<Duration> sleeps = new ArrayList<>();
        SealCertificate sc = waiting(rp, sleeps).seal().waitForCertificate(ORG, REQ_ID, new SealWaitOptions(null, Duration.ofSeconds(2)));
        assertArrayEquals(der, sc.certificate());
        assertEquals(3, rp.seen.size());
        assertEquals(List.of(Duration.ofSeconds(2), Duration.ofSeconds(2)), sleeps);

        String[][] terminal = {{"REJECTED", ",\"decidedAt\":\"2026-11-09T05:01:00Z\"", ""}, {"EXPIRED", ",\"failure\":\"EXPIRED\"", "EXPIRED"},
            {"FAILED", ",\"failure\":\"SEAL_ISSUANCE_FAILED\"", "SEAL_ISSUANCE_FAILED"}, {"FAILED", ",\"failure\":\"SEAL_SERVICE_DISABLED\"", "SEAL_SERVICE_DISABLED"}};
        for (String[] t : terminal) {
            FakeRp x = seq(FakeRp.json(200, reqBody("PENDING", "")), FakeRp.json(200, reqBody(t[0], t[1])));
            try {
                waiting(x, new ArrayList<>()).seal().waitForCertificate(ORG, REQ_ID, null);
                fail(t[0]);
            } catch (EidException.SealRequestFailed e) {
                assertEquals(t[0], e.outcome());
                assertEquals(REQ_ID, e.requestId());
                assertEquals(t[2], e.failure());
                assertEquals(t[2].isEmpty() ? t[0] : t[2], e.code());
                assertEquals(2, x.seen.size());
            }
        }

        // Timeout: still PENDING → outcome TIMEOUT; the last sleep is cut to the deadline.
        FakeRp p = FakeRp.reply(200, reqBody("PENDING", ""));
        List<Duration> s2 = new ArrayList<>();
        try {
            waiting(p, s2).seal().waitForCertificate(ORG, REQ_ID, new SealWaitOptions(Duration.ofSeconds(7), Duration.ofSeconds(3)));
            fail();
        } catch (EidException.SealRequestFailed e) {
            assertEquals(SealCertificateRequest.STATUS_TIMEOUT, e.outcome());
            assertEquals("", e.failure());
        }
        assertEquals(List.of(Duration.ofSeconds(3), Duration.ofSeconds(3), Duration.ofSeconds(1)), s2);

        // 429 + Retry-After: waits max(interval, Retry-After) and goes on.
        FakeRp ra = seq(retryAfter(429, "{\"error\":\"хэт олон\",\"code\":\"RATE_LIMITED\"}", "9"), FakeRp.json(200, issuedBody(der)));
        List<Duration> s3 = new ArrayList<>();
        waiting(ra, s3).seal().waitForCertificate(ORG, REQ_ID, new SealWaitOptions(null, Duration.ofSeconds(1)));
        assertEquals(List.of(Duration.ofSeconds(9)), s3);
        // 404 SEAL_REQUEST_NOT_FOUND — no retry.
        FakeRp nf = FakeRp.reply(404, "{\"error\":\"олдсонгүй\",\"code\":\"SEAL_REQUEST_NOT_FOUND\"}");
        try {
            waiting(nf, new ArrayList<>()).seal().waitForCertificate(ORG, REQ_ID, null);
            fail();
        } catch (EidException.SealRequestNotFound e) {
            assertEquals(1, nf.seen.size());
        }
        // 503 SEAL_SERVICE_DISABLED with a proxy's Retry-After — never retried (Go TestSeal_ServiceDisabled).
        FakeRp dis = FakeRp.reply(503, "{}");
        dis.handler = q -> retryAfter(503, "{\"error\":\"x\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"issuance\"}", "1");
        try {
            waiting(dis, new ArrayList<>()).seal().waitForCertificate(ORG, REQ_ID, null);
            fail();
        } catch (EidException.SealServiceDisabled e) {
            assertFalse(e.retryable());
            assertEquals(EidErrorCodes.SEAL_SERVICE_ISSUANCE, e.service());
            assertEquals(1, dis.seen.size());
        }
        // Interrupt → Network cancelled, no request.
        FakeRp it = FakeRp.reply(200, reqBody("PENDING", ""));
        Thread.currentThread().interrupt();
        try {
            waiting(it, new ArrayList<>()).seal().waitForCertificate(ORG, REQ_ID, null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.cancelled());
            assertEquals(0, it.seen.size());
        } finally {
            Thread.interrupted();
        }
    }

    // Go TestSeal_RequestCertificateErrors + TestSeal_ConflictCodes + TestSeal_ServiceDisabled + TestSeal_Other503Unchanged
    @Test
    public void errorCodes() {
        byte[] d = sha256("doc");
        String[][] conflicts = {{"ORG_NOT_ACTIVE", "0"}, {"SEAL_NOT_ISSUED", "1"}, {"SEAL_CERT_REVOKED", "1"}, {"SEAL_KEY_UNAVAILABLE", "0"},
            {"SEAL_CERT_EXPIRED", "1"}, {"SEAL_CERT_NOT_YET_VALID", "1"}};
        for (String[] c : conflicts) {
            String body = "{\"error\":\"тамгалах боломжгүй\",\"code\":\"" + c[0] + "\"}";
            for (int get = 0; get <= Integer.parseInt(c[1]); get++) {
                FakeRp rp = FakeRp.reply(409, body);
                try {
                    if (get == 0) rp.client().seal().seal(ORG, d, HashAlgorithm.SHA_256);
                    else rp.client().seal().certificate(ORG);
                    fail(c[0]);
                } catch (EidException.Api e) {
                    assertEquals(409, e.status());
                    assertEquals(c[0], e.code());
                    assertFalse(e.retryable());
                    assertEquals(1, rp.seen.size());
                }
            }
        }
        try {
            FakeRp.reply(409, "{\"error\":\"ADMIN алга\",\"code\":\"SEAL_APPROVER_UNAVAILABLE\"}").client().seal().requestCertificate(ORG);
            fail();
        } catch (EidException.SealApproverUnavailable e) {
            assertEquals(409, e.status());
        }
        try {
            FakeRp.reply(503, "{\"error\":\"x\",\"code\":\"SEAL_SERVICE_DISABLED\",\"service\":\"sealing\"}").client().seal().seal(ORG, d, null);
            fail();
        } catch (EidException.SealServiceDisabled e) {
            assertEquals(EidErrorCodes.SEAL_SERVICE_SEALING, e.service());
            assertFalse(e.retryable());
        }
        try {
            FakeRp.reply(403, "{\"error\":\"идэвхгүй\",\"code\":\"ORG_NOT_ACTIVE\"}").client().seal().seal(ORG, d, null);
            fail();
        } catch (EidException.Forbidden e) {
            assertEquals("onBehalfOf-style 403 ORG_NOT_ACTIVE stays Forbidden", "ORG_NOT_ACTIVE", e.code());
        }
        FakeRp other = new FakeRp(q -> retryAfter(503, "{\"error\":\"state\",\"code\":\"STATE_UNAVAILABLE\"}", "5"));
        try {
            other.client().seal().requestCertificate(ORG);
            fail();
        } catch (EidException.Api e) {
            assertTrue(e.retryable());
            assertEquals("", e.service());
        }
        assertEquals(List.of("ORG_NOT_ACTIVE", "SEAL_NOT_ISSUED", "SEAL_CERT_REVOKED", "SEAL_KEY_UNAVAILABLE", "SEAL_CERT_EXPIRED",
            "SEAL_CERT_NOT_YET_VALID", "SEAL_APPROVER_UNAVAILABLE", "SEAL_REQUEST_NOT_FOUND", "SEAL_SERVICE_DISABLED"), EidErrorCodes.SEAL);
    }

    static String grantBody(String status, String extra) {
        return "{\"grantId\":\"g-1\",\"orgEtsi\":\"" + ORG + "\",\"status\":\"" + status + "\",\"expiresAt\":\"2026-11-20T05:07:00Z\"" + extra + "}";
    }

    // Go seal_grant_test.go TestSealGrant_Request, _StatusApproved, _ErrorCodes, _Wait, _WaitTerminal
    @Test
    public void grants() {
        FakeRp rp = FakeRp.reply(202, grantBody("PENDING", ""));
        SealGrant g = rp.client().seal().requestGrant("  " + ORG + " ", " sess-1 ");
        FakeRp.assertRequest(rp.last(), "POST", "/seal/grants");
        FakeRp.assertJsonEquals("grant body", "{\"orgEtsi\":\"" + ORG + "\",\"sessionId\":\"sess-1\"}", rp.lastBody());
        assertEquals(SealGrant.STATUS_PENDING, g.status());
        assertEquals(Instant.parse("2026-11-20T05:07:00Z"), g.expiresAt());
        for (String[] bad : new String[][] {{"", "s"}, {ORG, " "}, {null, "s"}}) {
            try {
                rp.client().seal().requestGrant(bad[0], bad[1]);
                fail();
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        try {
            rp.client().seal().grantStatus(" ");
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        assertEquals(1, rp.seen.size());

        FakeRp st = FakeRp.reply(200, grantBody("APPROVED", ",\"approvedAt\":\"2026-11-20T05:01:00Z\""));
        SealGrant a = st.client().seal().grantStatus("g-1");
        FakeRp.assertRequest(st.last(), "GET", "/seal/grants/g-1");
        assertEquals(Instant.parse("2026-11-20T05:01:00Z"), a.approvedAt());
        try {
            FakeRp.reply(200, "{\"status\":\"PENDING\"}").client().seal().grantStatus("g-1");
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.SEAL_RESPONSE, e.reason());
        }

        String[][] codes = {{"403", "NOT_ORG_CEO"}, {"403", "RP_NOT_REGISTERED"}, {"404", "AUTH_SESSION_NOT_FOUND"}, {"409", "AUTH_SESSION_WRONG_FLOW"},
            {"409", "AUTH_SESSION_NOT_COMPLETED"}, {"409", "AUTH_SESSION_TOO_OLD"}, {"409", "AUTH_SESSION_ALREADY_USED"}, {"409", "RP_NOT_ACTIVE"},
            {"409", "SEAL_GRANT_ALREADY_APPROVED"}, {"409", "RP_PERMISSIONS_FULL"}, {"404", "SEAL_GRANT_NOT_FOUND"}, {"404", "ORG_NOT_FOUND"}};
        for (String[] c : codes) {
            try {
                FakeRp.reply(Integer.parseInt(c[0]), "{\"error\":\"x\",\"code\":\"" + c[1] + "\"}").client().seal().requestGrant(ORG, "s");
                fail(c[1]);
            } catch (EidException e) {
                assertEquals(c[1], e.code());
                assertEquals(Integer.parseInt(c[0]), e.status());
                if (c[0].equals("403")) assertTrue(e instanceof EidException.Forbidden);
            }
        }

        FakeRp w = seq(FakeRp.json(200, grantBody("PENDING", "")), FakeRp.json(200, grantBody("APPROVED", "")));
        List<Duration> sleeps = new ArrayList<>();
        assertEquals(SealGrant.STATUS_APPROVED, waiting(w, sleeps).seal().waitForGrant("g-1", null).status());
        assertEquals(List.of(SealService.DEFAULT_POLL_INTERVAL), sleeps);
        for (String t : new String[] {"REJECTED", "EXPIRED", "FAILED", "REVOKED"}) {
            FakeRp x = seq(FakeRp.json(200, grantBody(t, t.equals("FAILED") ? ",\"failure\":\"PUSH_FAILED\"" : "")));
            try {
                waiting(x, new ArrayList<>()).seal().waitForGrant("g-1", null);
                fail(t);
            } catch (EidException.SealGrantFailed e) {
                assertEquals(t, e.outcome());
                assertEquals("g-1", e.grantId());
                assertEquals(t.equals("FAILED") ? "PUSH_FAILED" : "", e.failure());
            }
        }
        FakeRp pend = FakeRp.reply(200, grantBody("PENDING", ""));
        try {
            waiting(pend, new ArrayList<>()).seal().waitForGrant("g-1", new SealWaitOptions(Duration.ofSeconds(5), Duration.ofSeconds(2)));
            fail();
        } catch (EidException.SealGrantFailed e) {
            assertEquals(SealGrant.STATUS_TIMEOUT, e.outcome());
        }
        assertEquals(List.of("RP_NOT_REGISTERED", "NOT_ORG_CEO", "AUTH_SESSION_NOT_FOUND", "ORG_NOT_FOUND", "AUTH_SESSION_WRONG_FLOW",
            "AUTH_SESSION_NOT_COMPLETED", "AUTH_SESSION_TOO_OLD", "AUTH_SESSION_ALREADY_USED", "ORG_NOT_ACTIVE", "RP_NOT_ACTIVE",
            "SEAL_GRANT_ALREADY_APPROVED", "RP_PERMISSIONS_FULL", "SEAL_APPROVER_UNAVAILABLE", "SEAL_GRANT_NOT_FOUND"), EidErrorCodes.SEAL_GRANT);
    }

    // Go contract_test.go TestContractSealDTO (static): the SDK sends only CA dto.SealRequest members.
    @Test
    public void sealDtoMembers() {
        Object[] c = sealCert(TestCerts.KU_NON_REPUDIATION);
        FakeRp rp = sealReply((KeyPair) c[0], (byte[]) c[1]);
        rp.client().seal().seal(ORG, new byte[32], null);
        assertEquals(Set.of("digest", "hashType"), rp.lastJson().keySet());
    }
}
