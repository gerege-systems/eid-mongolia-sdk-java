package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * TokenService: issuance (issue / preview / result / info), verifyTokenCertificates, token sign-in (challenge, digest,
 * verify with the SDK's own checks), tokenLimitOf (ports of Go portal_gaps_test.go TestTokenCertificate,
 * TestTokenCertificateInfo, TestTokenCertificateAppTransaction, TestTokenCertificatePreview, TestTokenAuth; TS token tests).
 */
public class TokenServiceTest {
    static final String RP = "2d87bd3a-1303-41bf-81bd-37d6b92fb7bc";
    static final TestCerts.Ca CA = new TestCerts.Ca("TEST ONLY Token Root");

    /** Go {@code tokenKeys}: a CSR + a certificate for that key (auth profile) issued by the test CA. */
    static Object[] tokenKeys(String serial) {
        KeyPair k = TestCerts.ec();
        TestCerts.Spec s = CA.issue(k).attr("2.5.4.6", "MN").cn("DORJ,BAT," + serial).attr("2.5.4.5", serial)
            .attr("2.5.4.42", "BAT").attr("2.5.4.4", "DORJ");
        s.ku = TestCerts.KU_DIGITAL_SIGNATURE | TestCerts.KU_KEY_ENCIPHERMENT | TestCerts.KU_NON_REPUDIATION;
        s.eku = List.of(TestCerts.EKU_CLIENT_AUTH, TestCerts.EKU_EMAIL);
        return new Object[] {TestCerts.csr(k), TestCerts.cert(s), k};
    }

    static String hexUpper(byte[] b) {
        return Text.hex(EidCrypto.digest("SHA-256", b)).toUpperCase(Locale.ROOT);
    }

    static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    // Go TestTokenCertificate
    @Test
    public void issueResultVerifyLimit() {
        Object[] a = tokenKeys("PNOMN-12345678");
        Object[] s = tokenKeys("PNOMN-12345678");
        byte[] csrA = (byte[]) a[0];
        byte[] csrS = (byte[]) s[0];
        FakeRp rp = FakeRp.reply(200, "{\"sessionID\":\"ts1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"04817\"},\"csrAuthSha256\":\""
            + hexUpper(csrA) + "\",\"csrSignSha256\":\"" + hexUpper(csrS) + "\",\"expiresAt\":\"2026-10-12T16:41:34+08:00\"}");
        TokenCertStart st = rp.client().token().issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "EP2003-0042A1", null, null, null));
        assertEquals("ts1", st.sessionId());
        assertEquals("04817", st.vc());
        assertEquals(hexUpper(csrA).toLowerCase(Locale.ROOT), st.csrAuthSha256());
        assertTrue(st.supersedes().isEmpty());
        FakeRp.assertRequest(rp.last(), "POST", "/token/certificate");
        FakeRp.assertJsonEquals("issue body", "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\","
            + "\"signer\":{\"etsi\":\"PNOMN-12345678\"},\"csrAuth\":\"" + b64(csrA) + "\",\"csrSign\":\"" + b64(csrS)
            + "\",\"tokenSerial\":\"EP2003-0042A1\",\"onBehalfOf\":\"\",\"flow\":\"notification\"}", rp.lastBody());

        FakeRp wrong = FakeRp.reply(200, "{\"sessionID\":\"ts1\",\"csrAuthSha256\":\"" + hexUpper(csrS) + "\",\"csrSignSha256\":\"" + hexUpper(csrS) + "\"}");
        try {
            wrong.client().token().issueCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", "L", "NTRMN-1", null));
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.TOKEN_RESPONSE, e.reason());
        }
        FakeRp.assertJsonEquals("label + onBehalfOf", "{\"relyingPartyUUID\":\"rp-uuid\",\"relyingPartyName\":\"Гэрээний систем\","
            + "\"signer\":{\"etsi\":\"PNOMN-1\"},\"csrAuth\":\"" + b64(csrA) + "\",\"csrSign\":\"" + b64(csrS)
            + "\",\"tokenSerial\":\"x\",\"tokenLabel\":\"L\",\"onBehalfOf\":\"NTRMN-1\",\"flow\":\"notification\"}", wrong.lastBody());
        try {
            rp.client().token().issueCertificate(new TokenCertInput(null, null, null, null, null, null, null));
            fail("empty input");
        } catch (IllegalArgumentException expected) {
            // ok
        }

        String result = "{\"status\":\"ISSUED\",\"auth\":{\"certificate\":\"" + b64((byte[]) a[1]) + "\",\"serialHex\":\"A\"},"
            + "\"sign\":{\"certificate\":\"" + b64((byte[]) s[1]) + "\",\"serialHex\":\"S\"},\"chain\":[\"x\"],\"organization\":null,"
            + "\"keyMedium\":\"TOKEN\",\"certificateLevel\":\"ADVANCED\"}";
        FakeRp res = FakeRp.reply(200, result);
        TokenCertResult r = res.client().token().certificateResult("ts1");
        FakeRp.assertRequest(res.last(), "GET", "/token/certificate/ts1");
        assertEquals(TokenService.RESULT_TIMEOUT, res.last().timeout());
        assertEquals("ISSUED", r.status());
        assertNull(r.organization());
        assertEquals("TOKEN", r.keyMedium());
        assertEquals(List.of("x"), r.chain());
        assertFalse(r.rawJson().isEmpty());
        TokenService.verifyTokenCertificates(r, csrA, csrS);
        try {
            TokenService.verifyTokenCertificates(r, csrS, csrA);
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.TOKEN_CERTIFICATE, e.reason());
        }
        try {
            TokenService.verifyTokenCertificates(new TokenCertResult("", null, null, List.of(), "", null, "", "", ""), csrA, csrS);
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.TOKEN_CERTIFICATE, e.reason());
        }
        try {
            TokenService.verifyTokenCertificates(r, new byte[] {0x30, 0}, csrS);
            fail("bad CSR");
        } catch (IllegalArgumentException expected) {
            // ok
        }

        FakeRp lim = FakeRp.reply(409, "{\"error\":\"хязгаар\",\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"ORGANIZATION\",\"limit\":1,\"organization\":\"NTRMN-6235972\"}");
        try {
            lim.client().token().issueCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, null, null));
            fail();
        } catch (EidException.Api e) {
            TokenLimit l = TokenService.tokenLimitOf(e);
            assertEquals(new TokenLimit(TokenService.KIND_ORGANIZATION, 1, "NTRMN-6235972"), l);
        }
        String[] notLimits = {"{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\"}", "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"ORGANIZATION\",\"limit\":1}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"X\",\"limit\":1}", "{\"code\":\"TOKEN_IN_USE\",\"kind\":\"PERSONAL\",\"limit\":1}",
            "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\",\"limit\":-1}"};
        for (String body : notLimits) {
            try {
                FakeRp.reply(409, body).client().token().issueCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, null, null));
                fail();
            } catch (EidException.Api e) {
                assertNull(body, TokenService.tokenLimitOf(e));
            }
        }
        try {
            FakeRp.reply(409, "{\"code\":\"TOKEN_LIMIT_REACHED\",\"kind\":\"PERSONAL\",\"limit\":0}").client().token()
                .issueCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, null, null));
            fail();
        } catch (EidException.Api e) {
            assertEquals(0, TokenService.tokenLimitOf(e).limit());
        }
        assertNull(TokenService.tokenLimitOf(new IllegalStateException()));
        try {
            FakeRp.reply(409, "{\"error\":\"…\",\"code\":\"TOKEN_SCOPE_CHANGE\"}").client().token()
                .issueCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, "NTRMN-1", null));
            fail();
        } catch (EidException.Api e) {
            assertEquals(EidErrorCodes.TOKEN_SCOPE_CHANGE, e.code());
            assertFalse(e.retryable());
            assertNull(TokenService.tokenLimitOf(e));
        }
    }

    // Go TestTokenCertificateAppTransaction + TestTokenCertificatePreview
    @Test
    public void appTransactionAndPreview() {
        byte[] csrA = (byte[]) tokenKeys("PNOMN-12345678")[0];
        byte[] csrS = (byte[]) tokenKeys("PNOMN-12345678")[0];
        String ok = "{\"sessionID\":\"ts1\",\"csrAuthSha256\":\"" + hexUpper(csrA).toLowerCase(Locale.ROOT) + "\",\"csrSignSha256\":\""
            + hexUpper(csrS).toLowerCase(Locale.ROOT) + "\"";
        FakeRp rp = FakeRp.reply(200, ok + "}");
        TokenService t = rp.client().token();
        t.issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "EP2003-0042A1", null, null, "eyJhbGciOiJFUzI1NiJ9.e30.sig"));
        assertEquals("eyJhbGciOiJFUzI1NiJ9.e30.sig", rp.lastJson().optString("appTransaction"));
        TokenCertStart sup = FakeRp.reply(200, ok + ",\"supersedes\":[{\"tokenSerial\":\"EP2003-0001\"}]}").client().token()
            .issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "EP2003-0042A1", null, null, null));
        assertEquals(List.of(new TokenSupersede("EP2003-0001")), sup.supersedes());
        String max = "a".repeat(TokenService.MAX_APP_TRANSACTION_BYTES);
        t.issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "x", null, null, max));
        int n = rp.seen.size();
        try {
            t.issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "x", null, null, max + "a"));
            fail();
        } catch (IllegalArgumentException expected) {
            assertEquals("not sent", n, rp.seen.size());
        }
        try {
            FakeRp.reply(400, "{\"error\":\"апп баталгаа хүчингүй\",\"code\":\"APP_ATTESTATION_INVALID\"}").client().token()
                .issueCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "x", null, null, "x.y.z"));
            fail();
        } catch (EidException.Api e) {
            assertEquals(400, e.status());
            assertEquals(EidErrorCodes.APP_ATTESTATION_INVALID, e.code());
        }

        FakeRp pv = FakeRp.reply(200, "{\"dryRun\":true,\"supersedes\":[{\"tokenSerial\":\"EP2003-0001\"}]}");
        TokenCertPreview p = pv.client().token().previewCertificate(new TokenCertInput("PNOMN-12345678", csrA, csrS, "EP2003-0042A2", null, null, "a.b.c"));
        assertEquals("EP2003-0001", p.supersedes().get(0).tokenSerial());
        Json.Obj body = pv.lastJson();
        assertEquals(Boolean.TRUE, body.get("dryRun"));
        assertEquals("EP2003-0042A2", body.optString("tokenSerial"));
        assertEquals("a.b.c", body.optString("appTransaction"));
        assertTrue(FakeRp.reply(200, "{\"dryRun\":true}").client().token()
            .previewCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, null, null)).supersedes().isEmpty());
        try {
            FakeRp.reply(200, "{\"sessionID\":\"x\"}").client().token().previewCertificate(new TokenCertInput("PNOMN-1", csrA, csrS, "x", null, null, null));
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.TOKEN_RESPONSE, e.reason());
        }
    }

    // Go TestTokenCertificateInfo
    @Test
    public void certificateInfo() {
        FakeRp rp = FakeRp.reply(200, "{\"version\":\"v3\",\"tokenCertificate\":{\"certificateLevel\":\"ADVANCED\",\"enabled\":true,"
            + "\"issue\":\"https://rp.eidmongolia.mn/token/certificate\",\"keyAlgorithm\":\"EC P-256 (ecdsa-with-SHA256)\",\"onBehalfOf\":\"optional\","
            + "\"permission\":\"TOKEN_ISSUE\",\"result\":\"https://rp.eidmongolia.mn/token/certificate/{sessionID}\",\"scopeLockedOnRenewal\":true,"
            + "\"appTransaction\":\"optional\",\"personalAutoSupersede\":true,\"dryRun\":true}}");
        TokenCertInfo i = rp.client().token().certificateInfo();
        FakeRp.assertRequest(rp.last(), "GET", "/.well-known/eid");
        assertTrue(i.enabled() && i.scopeLockedOnRenewal() && i.personalAutoSupersede() && i.dryRun());
        assertEquals("TOKEN_ISSUE", i.permission());
        assertEquals("optional", i.appTransaction());
        assertFalse(i.rawJson().isEmpty());
        TokenCertInfo old = FakeRp.reply(200, "{\"version\":\"v3\"}").client().token().certificateInfo();
        assertFalse(old.enabled() || old.scopeLockedOnRenewal());
        assertEquals("", old.appTransaction());
    }

    /** The token's raw r‖s over {@link TokenService#tokenAuthDigest}. */
    static byte[] rawSig(KeyPair k, TokenAuthChallenge ch) throws Exception {
        Signature s = Signature.getInstance("NONEwithECDSA");
        s.initSign(k.getPrivate());
        s.update(TokenService.tokenAuthDigest(ch.rpUuid(), ch.challenge()));
        List<Der.Tlv> rs = Der.parse(s.sign()).children();
        byte[] out = new byte[64];
        byte[] r = new BigInteger(1, rs.get(0).value()).toByteArray();
        byte[] q = new BigInteger(1, rs.get(1).value()).toByteArray();
        System.arraycopy(r, Math.max(0, r.length - 32), out, 32 - Math.min(32, r.length), Math.min(32, r.length));
        System.arraycopy(q, Math.max(0, q.length - 32), out, 64 - Math.min(32, q.length), Math.min(32, q.length));
        return out;
    }

    static EidClient tokenClient(FakeRp rp, TrustConfig trust) {
        return EidClient.builder(new Credentials(RP, "x", "s")).transport(rp).clock(rp.clock).trust(trust).build();
    }

    // Go TestTokenAuth
    @Test
    public void tokenAuth() throws Exception {
        byte[] d = TokenService.tokenAuthDigest(RP, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=");
        assertEquals("docs/TOKEN_AUTH.md vector", "a88f9803b82f9e0701752360184f18f2035bc2447372283e3fa009fe2cfeeef5", Text.hex(d));
        for (String[] bad : new String[][] {{RP.toUpperCase(Locale.ROOT), "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="}, {RP, "AAEC"}}) {
            try {
                TokenService.tokenAuthDigest(bad[0], bad[1]);
                fail();
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }

        FakeRp chRp = FakeRp.reply(200, "{\"challengeId\":\"c1\",\"challenge\":\"q3J0\",\"rpUUID\":\"" + RP + "\",\"expiresAt\":\"2026-10-12T08:42:10Z\"}");
        TokenAuthChallenge got = chRp.client().token().authChallenge();
        FakeRp.assertRequest(chRp.last(), "POST", "/token/auth/challenge");
        FakeRp.assertJsonEquals("challenge body", "{\"relyingPartyName\":\"Гэрээний систем\",\"relyingPartyUUID\":\"rp-uuid\"}", chRp.lastBody());
        assertEquals(Instant.parse("2026-10-12T08:42:10Z"), got.expiresAt());

        TokenAuthChallenge chal = new TokenAuthChallenge("c1", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", RP, null);
        Object[] tk = tokenKeys("PNOMN-55667788");
        byte[] cert = (byte[]) tk[1];
        KeyPair key = (KeyPair) tk[2];
        byte[] sig = rawSig(key, chal);
        TrustConfig okTrust = TrustConfig.builder().trustAnchorsPem(CA.pem()).allowAnyIssuer(true).build();
        String ok = "{\"result\":{\"endResult\":\"OK\"},\"identity\":{\"etsi\":\"PNOMN-55667788\",\"givenName\":\"Бат\",\"surname\":\"Болд\"},"
            + "\"cert\":{\"serialHex\":\"4f1c\",\"notAfter\":\"2027-10-12T08:40:00Z\"},\"organization\":{\"etsi\":\"NTRMN-1\",\"name\":\"X\"}}";
        FakeRp v = FakeRp.reply(200, ok);
        TokenAuthResult res = tokenClient(v, okTrust).token().authVerify(chal, cert, sig);
        assertEquals("Болд", res.identity().surname());
        assertEquals("4f1c", res.serialHex());
        assertEquals("NTRMN-1", res.organization().etsi());
        assertEquals(Instant.parse("2027-10-12T08:40:00Z"), res.notAfter());
        FakeRp.assertRequest(v.last(), "POST", "/token/auth/verify");
        FakeRp.assertJsonEquals("verify body", "{\"challengeId\":\"c1\",\"certificate\":\"" + b64(cert) + "\",\"signature\":\"" + b64(sig) + "\"}",
            v.lastBody());

        for (String reply : new String[] {ok.replace("PNOMN-55667788", "PNOMN-99999999"), ok.replace("\"OK\"", "\"DENIED\"")}) {
            try {
                tokenClient(FakeRp.reply(200, reply), okTrust).token().authVerify(chal, cert, sig);
                fail(reply);
            } catch (EidException.Validation e) {
                assertEquals(ValidationReasons.TOKEN_RESULT, e.reason());
                assertFalse("no PII", e.getMessage().contains("PNOMN-"));
            }
        }

        TokenAuthChallenge other = new TokenAuthChallenge("c1", "AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", RP, null);
        TokenAuthChallenge otherRp = new TokenAuthChallenge("c1", chal.challenge(), "00000000-0000-4000-8000-000000000000", null);
        // the token's SIGN certificate (KU DS + NR, no EKU) for sign-in
        KeyPair sk = TestCerts.ec();
        TestCerts.Spec signSpec = CA.issue(sk).attr("2.5.4.6", "MN").cn("DORJ,BAT,PNOMN-55667788").attr("2.5.4.5", "PNOMN-55667788");
        signSpec.ku = TestCerts.KU_DIGITAL_SIGNATURE | TestCerts.KU_NON_REPUDIATION;
        byte[] signCert = TestCerts.cert(signSpec);
        // two SERIALNUMBERs (cross-SDK hardening)
        KeyPair dk = TestCerts.ec();
        TestCerts.Spec dupSpec = CA.issue(dk).attr("2.5.4.6", "MN").cn("DORJ,BAT,PNOMN-55667788").attr("2.5.4.5", "PNOMN-55667788")
            .attr("2.5.4.5", "PNOMN-99999999");
        dupSpec.ku = TestCerts.KU_DIGITAL_SIGNATURE;
        dupSpec.eku = List.of(TestCerts.EKU_CLIENT_AUTH);
        byte[] dupCert = TestCerts.cert(dupSpec);
        Object[][] cases = {
            {"zero signature", chal, cert, new byte[64], okTrust, ValidationReasons.TOKEN_SIGNATURE},
            {"other challenge", other, cert, sig, okTrust, ValidationReasons.TOKEN_SIGNATURE},
            {"other RP", otherRp, cert, rawSig(key, otherRp), okTrust, ValidationReasons.TOKEN_CHALLENGE},
            {"default issuer allowlist", chal, cert, sig, TrustConfig.builder().trustAnchorsPem(CA.pem()).build(), ValidationReasons.ISSUER_NOT_ALLOWED},
            {"no anchor", chal, cert, sig, null, ValidationReasons.TRUST_NO_ANCHOR},
            {"sign certificate", chal, signCert, rawSig(sk, chal), okTrust, ValidationReasons.PURPOSE_AUTH_CLIENT_AUTH},
            {"two SERIALNUMBERs", chal, dupCert, rawSig(dk, chal), okTrust, ValidationReasons.CERT_SUBJECT_AMBIGUOUS},
        };
        for (Object[] c : cases) {
            FakeRp x = FakeRp.reply(200, ok);
            try {
                tokenClient(x, (TrustConfig) c[4]).token().authVerify((TokenAuthChallenge) c[1], (byte[]) c[2], (byte[]) c[3]);
                fail((String) c[0]);
            } catch (EidException.Validation e) {
                assertEquals((String) c[0], c[5], e.reason());
            }
            assertEquals(c[0] + ": nothing sent to the CA", 0, x.seen.size());
        }
        try {
            tokenClient(v, okTrust).token().authVerify(chal, "junk".getBytes(java.nio.charset.StandardCharsets.US_ASCII), sig);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            tokenClient(v, okTrust).token().authVerify(null, cert, sig);
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            tokenClient(FakeRp.reply(410, "{\"error\":\"x\",\"code\":\"CHALLENGE_EXPIRED\"}"), okTrust).token().authVerify(chal, cert, sig);
            fail();
        } catch (EidException.Api e) {
            assertEquals(EidErrorCodes.CHALLENGE_EXPIRED, e.code());
        }
        assertNotNull(EidErrorCodes.TOKEN);
        assertEquals(39, EidErrorCodes.TOKEN.size());
    }
}
