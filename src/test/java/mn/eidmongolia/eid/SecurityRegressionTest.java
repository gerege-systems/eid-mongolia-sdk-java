package mn.eidmongolia.eid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.function.Function;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Ocsp;
import mn.eidmongolia.eid.pades.EidQr;
import mn.eidmongolia.eid.pades.EidQrException;
import org.junit.Test;

/** Regression tests of the PR #7 security review (dual certificate parser, weak chains, verifier, key floor, nulls). */
public class SecurityRegressionTest {
    private static final Instant NOW = Instant.parse("2026-10-14T04:00:00Z");

    private static Json.Obj rpCase(String name) {
        for (Object o : ConformanceTest.json("rp-validate/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals(name)) return c;
        }
        throw new IllegalStateException(name);
    }

    private static ResponseValidator validator(Json.Obj c) {
        return ConformanceTest.validator(ConformanceTest.json("rp-validate/cases.json").optObj("trust").optObj(c.optString("trust")), NOW);
    }

    /** The case's session JSON with cert.value / signature.value / … replaced. */
    private static SessionResult session(Json.Obj c, Function<Json.Obj, Json.Obj> edit) {
        Json.Obj s = (Json.Obj) Json.parse(FakeRp.text(c.get("session")));
        return SessionService.parseSessionResult(FakeRp.text(edit.apply(s)));
    }

    private static Json.Obj set(Json.Obj o, String block, String key, String value) {
        Json.Obj b = o.optObj(block);
        b.values.set(b.keys.lastIndexOf(key), value);
        return o;
    }

    private static byte[] pki(String name) {
        return Cert.pemSingle(ConformanceTest.bytes("pki/" + name));
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static void expect(Runnable r, String reason) {
        try {
            r.run();
            fail("accepted; " + reason + " expected");
        } catch (EidException.Validation e) {
            assertEquals(e.getMessage(), reason, e.reason());
        }
    }

    private static void runAuth(Json.Obj c, SessionResult r) {
        validator(c).validateAuth(r, ConformanceTest.acsp(c.optObj("acsp")), ValidateAuthOptions.NONE);
    }

    private static void runSign(Json.Obj c, SessionResult r) {
        validator(c).validateSign(r, c.optString("digest"), HashAlgorithm.fromWire(c.optString("hashAlgorithm")), ValidateSignOptions.NONE);
    }

    // ── MUST FIX 1: one certificate, one parser ──

    @Test
    public void dualParserWrapperRejected() throws Exception {
        byte[] real = pki("leaf-auth.pem");
        byte[] crafted = TestPki.dualParserWrapper(real, TestPki.victimTbs(real));
        // The attack vector is real: the JDK factory reads the embedded PEM (the genuine certificate) …
        X509Certificate jdk = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(crafted));
        assertArrayEquals(real, jdk.getEncoded());
        // … so the single entry point refuses anything that is not byte-identical DER.
        for (byte[] bad : List.of(crafted, Der.concat(real, new byte[] {0}), TestPki.pem(real).getBytes(StandardCharsets.US_ASCII),
            ("\n" + TestPki.pem(real)).getBytes(StandardCharsets.US_ASCII), new byte[0])) {
            try {
                Cert.parse(bad);
                fail("parsed " + bad.length + " bytes");
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertArrayEquals(real, Cert.parse(real).raw);

        // validateAuth / validateSign / validateCertificateChoice: cert.malformed before anything reads the certificate.
        Json.Obj auth = rpCase("auth-pss-sha512-qr");
        for (byte[] bad : List.of(crafted, Der.concat(real, new byte[] {0}), TestPki.pem(real).getBytes(StandardCharsets.US_ASCII))) {
            expect(() -> runAuth(auth, session(auth, s -> set(s, "cert", "value", b64(bad)))), ValidationReasons.CERT_MALFORMED);
        }
        byte[] sign = pki("leaf-sign.pem");
        byte[] craftedSign = TestPki.dualParserWrapper(sign, TestPki.victimTbs(sign));
        Json.Obj sc = rpCase("sign-pss-sha256");
        expect(() -> runSign(sc, session(sc, s -> set(s, "cert", "value", b64(craftedSign)))), ValidationReasons.CERT_MALFORMED);
        Json.Obj cc = rpCase("certchoice-sign-certificate");
        expect(() -> validator(cc).validateCertificateChoice(session(cc, s -> set(s, "cert", "value", b64(craftedSign))), "x"),
            ValidationReasons.CERT_MALFORMED);
        expect(() -> validator(cc).validateCertificateChoice(session(cc, s -> set(s, "cert", "value",
            b64(TestPki.pem(sign).getBytes(StandardCharsets.US_ASCII)))), "x"), ValidationReasons.CERT_MALFORMED);
    }

    /** An OCSP response embedding the wrapper as its responder certificate is refused (parse), never trusted. */
    @Test
    public void dualParserOcspResponder() {
        Json.Obj c = null;
        for (Object o : ConformanceTest.json("ocsp/cases.json").optArr("cases")) {
            if (((Json.Obj) o).optString("name").equals("delegated-responder")) c = (Json.Obj) o;
        }
        assertNotNull(c);
        Json.Obj http = c.optObj("http");
        String key = http.keySet().iterator().next();
        byte[] der = Base64.getDecoder().decode(http.optObj(key).optString("bodyB64"));
        // OCSPResponse { status, [0] { ResponseBytes { oid, OCTET { BasicOCSPResponse { tbs, alg, sig, [0] { certs } } } } } }
        List<Der.Tlv> top = Der.parse(der).children();
        List<Der.Tlv> rb = top.get(1).child(0).children();
        List<Der.Tlv> basic = Der.parse(rb.get(1).value()).children();
        byte[] responder = basic.get(3).child(0).child(0).encoded();
        byte[] fakeTbs = Der.parse(responder).child(0).encoded();
        byte[] crafted = TestPki.dualParserWrapper(responder, fakeTbs);
        byte[] newBasic = Der.seq(basic.get(0).encoded(), basic.get(1).encoded(), basic.get(2).encoded(),
            Der.tlv(Der.ctx(0), Der.seq(crafted)));
        byte[] body = Der.seq(top.get(0).encoded(), Der.tlv(Der.ctx(0), Der.seq(rb.get(0).encoded(), Der.octets(newBasic))));
        Cert leaf = Cert.parse(pki("leaf-auth.pem"));
        Cert ca04 = Cert.parse(pki("04-eid.pem"));
        try {
            Ocsp.parseResponseForCert(body, leaf, ca04);
            fail();
        } catch (Ocsp.ParseException e) {
            assertEquals(Ocsp.KIND_PARSE, e.kind);
        }
        try {
            Ocsp.parseForCert(body, leaf, ca04); // the PAdES LTV parser
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
        Json.Obj rep = new Json.Obj();
        rep.keys.add("status");
        rep.values.add(new Json.Num("200"));
        rep.keys.add("contentType");
        rep.values.add("application/ocsp-response");
        rep.keys.add("bodyB64");
        rep.values.add(b64(body));
        Json.Obj h = new Json.Obj();
        h.keys.add(key);
        h.values.add(rep);
        OcspRevocationChecker check = OcspRevocationChecker.builder().transport(ConformanceTest.replay(h, new ArrayList<>()))
            .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
        try {
            check.check(leaf.x509, ca04.x509);
            fail();
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.PARSE, e.kind());
        }
    }

    /** «My QR»: an x5c leaf that is not byte-identical DER is a header error, not a certificate. */
    @Test
    public void dualParserMyQr() {
        byte[] sign = pki("leaf-sign.pem");
        byte[] crafted = TestPki.dualParserWrapper(sign, TestPki.victimTbs(sign));
        for (byte[] leaf : List.of(crafted, Der.concat(sign, new byte[] {0}))) {
            String header = "{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + b64(leaf) + "\",\"" + b64(pki("04-eid.pem")) + "\"]}";
            String jws = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8)) + ".e30.AAAA";
            try {
                EidQr.verify(jws, new EidQr.Expect("00000000-0000-4000-8000-000000000001", "sid", "nonce", null, NOW));
                fail();
            } catch (EidQrException e) {
                assertEquals(EidQrException.HEADER_INVALID, e.code());
            }
        }
    }

    /** «My QR» chain: the validator's fail-closed rules (unknown critical extension, name constraints, pathLen). */
    @Test
    public void myQrChainFailClosed() {
        String[][] cases = {
            {"leaf-auth-under-name-constraints.pem", "ca-name-constraints.pem", "name constraints"},
            {"leaf-auth-under-unknown-critical.pem", "ca-unknown-critical.pem", "critical"},
            {"leaf-auth-under-inhibit-any-policy.pem", "ca-critical-inhibit-any-policy.pem", "critical"},
            {"leaf-auth-unknown-critical.pem", "04-eid.pem", "critical"},
            {"leaf-auth-below-pathlen.pem", "ca-below-pathlen-zero.pem", "pathLen"},
        };
        List<X509Certificate> anchors = List.of(ConformanceTest.cert(pki("01-root.pem")));
        List<X509Certificate> inter = List.of(ConformanceTest.cert(pki("02-national.pem")), ConformanceTest.cert(pki("04-eid.pem")));
        for (String[] c : cases) {
            String header = "{\"alg\":\"PS256\",\"typ\":\"eidmn-myqr+jwt\",\"x5c\":[\"" + b64(pki(c[0])) + "\",\"" + b64(pki(c[1])) + "\"]}";
            String jws = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8)) + ".e30.AAAA";
            try {
                EidQr.verify(jws, new EidQr.Expect("00000000-0000-4000-8000-000000000001", "sid", "nonce", null, NOW),
                    new EidQr.Trust(anchors, inter, null, (l, i) -> "good", false));
                fail(c[0]);
            } catch (EidQrException e) {
                assertEquals(c[0], EidQrException.CHAIN_INVALID, e.code());
                assertTrue(c[0] + ": " + e.getMessage(), e.getMessage().contains(c[2]));
            }
        }
    }

    // ── SHOULD FIX 2 / 4: chain signature algorithms, key sizes ──

    private static SessionResult choice(byte[] leaf) {
        return SessionService.parseSessionResult("{\"state\":\"COMPLETE\",\"result\":{\"endResult\":\"OK\",\"documentNumber\":\"PNOMN-TEST\"},"
            + "\"cert\":{\"value\":\"" + b64(leaf) + "\",\"certificateLevel\":\"ADVANCED\"}}");
    }

    private static ResponseValidator anchoredAt(byte[] root) {
        return new ResponseValidator(TrustConfig.builder().trustAnchorsPem(TestPki.pem(root)).intermediatesPem(List.of())
            .allowAnyIssuer(true).requiredLevel(CertificateLevel.ADVANCED).build(), Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    public void weakChainSignatureAndSmallCaKey() {
        KeyPair ca = TestPki.rsa(2048);
        KeyPair leaf = TestPki.rsa(2048);
        byte[] root = TestPki.cert("TEST ONLY Root", "TEST ONLY Root", ca, ca.getPrivate(), TestPki.SHA256_RSA, true, 1);
        byte[] good = TestPki.cert("TEST ONLY Signer", "TEST ONLY Root", leaf, ca.getPrivate(), TestPki.SHA256_RSA, false, 2);
        byte[] sha1 = TestPki.cert("TEST ONLY Signer", "TEST ONLY Root", leaf, ca.getPrivate(), TestPki.SHA1_RSA, false, 3);
        assertEquals("PNOMN-TEST", anchoredAt(root).validateCertificateChoice(choice(good), "x").documentNumber());
        try {
            anchoredAt(root).validateCertificateChoice(choice(sha1), "x");
            fail("SHA-1 chain accepted");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.CHAIN_UNTRUSTED, e.reason());
            assertTrue(e.getMessage(), e.getMessage().contains("SHA-1"));
        }
        assertFalse(Cert.parse(sha1).strongSignatureAlgorithm());
        assertTrue(Cert.parse(sha1).signedByAllowingSha1(Cert.parse(root))); // the OCSP-responder rule keeps SHA-1 (x/crypto)

        KeyPair small = TestPki.rsa(1024);
        byte[] smallRoot = TestPki.cert("TEST ONLY Small Root", "TEST ONLY Small Root", small, small.getPrivate(), TestPki.SHA256_RSA, true, 4);
        byte[] underSmall = TestPki.cert("TEST ONLY Signer", "TEST ONLY Small Root", leaf, small.getPrivate(), TestPki.SHA256_RSA, false, 5);
        expect(() -> anchoredAt(smallRoot).validateCertificateChoice(choice(underSmall), "x"), ValidationReasons.CHAIN_UNTRUSTED);
    }

    /** Every corpus and embedded RSA key is ≥ 2048 bits (the floor breaks no vector). */
    @Test
    public void corpusKeysAboveFloor() {
        int n = 0;
        for (String f : ConformanceTest.json("manifest.json").optObj("files").keySet()) {
            if (!f.startsWith("pki/")) continue;
            Cert c = Cert.parse(pki(f.substring(4)));
            if (c.isRsa()) assertTrue(f + " " + c.rsaBits(), c.rsaBits() >= ResponseValidator.MIN_RSA_BITS);
            n++;
        }
        assertTrue(n >= 30);
        List<String> embedded = new ArrayList<>(Roots.CITIZEN_INTERMEDIATES_PEM);
        embedded.add(Roots.NATIONAL_ROOT_CA_PEM);
        for (String p : embedded) {
            Cert c = Cert.parse(Cert.pemSingle(p.getBytes(StandardCharsets.US_ASCII)));
            assertTrue(c.rsaBits() >= ResponseValidator.MIN_RSA_BITS);
            assertTrue(c.strongSignatureAlgorithm());
        }
    }

    @Test
    public void rsaKeyFloorInSignatureVerification() throws Exception {
        KeyPair k = TestPki.rsa(1024);
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("doc".getBytes(StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("NONEwithRSA");
        s.initSign(k.getPrivate());
        s.update(Der.concat(new byte[] {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20}, digest));
        String sig = b64(s.sign());
        assertFalse(EidCrypto.verifyPrehashedSignature(digest, sig, k.getPublic(), "sha256WithRSAEncryption", "SHA-256"));
    }

    // ── SHOULD FIX 5: PSS on a modulus whose bit length is not a multiple of 8; flipped bytes ──

    @Test
    public void pssOddModulusLengths() throws Exception {
        byte[] msg = "rp-conformance odd modulus".getBytes(StandardCharsets.UTF_8);
        for (int bits : new int[] {2047, 2049, 3073}) {
            KeyPair k = TestPki.rsa(bits);
            assertEquals(bits, ((RSAPublicKey) k.getPublic()).getModulus().bitLength());
            Signature s = Signature.getInstance("RSASSA-PSS");
            s.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            s.initSign(k.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(msg);
            assertTrue(bits + " prehashed", Prehashed.rsaPssVerify((RSAPublicKey) k.getPublic(), digest, sig, "SHA-256"));
            byte[] d2 = digest.clone();
            d2[0] ^= 1;
            assertFalse(Prehashed.rsaPssVerify((RSAPublicKey) k.getPublic(), d2, sig, "SHA-256"));
            byte[] s2 = sig.clone();
            s2[s2.length / 2] ^= 1;
            assertFalse(Prehashed.rsaPssVerify((RSAPublicKey) k.getPublic(), digest, s2, "SHA-256"));
            // The public verifier adds the 2048-bit floor.
            assertEquals(bits >= 2048, EidCrypto.verifyPrehashedSignature(digest, b64(sig), k.getPublic(), "rsassa-pss", "SHA-256"));
            assertEquals(bits >= 2048, EidCrypto.verifyPayloadSignature(msg, b64(sig), k.getPublic(), "rsassa-pss", "SHA-256"));
        }
    }

    private static String flipB64(String b64, int index) {
        byte[] b = Base64.getDecoder().decode(b64);
        b[index < 0 ? b.length + index : index] ^= 1;
        return b64(b);
    }

    @Test
    public void flippedBytes() {
        Json.Obj auth = rpCase("auth-pss-sha512-qr");
        byte[] leaf = Base64.getDecoder().decode(auth.optObj("session").optObj("cert").optString("value"));
        // A leaf TBS byte (another PNOMN, DER still valid) and a leaf signature byte: no chain.
        byte[] tbsFlip = TestPki.replace(leaf, "PNOMN-999999990001", "PNOMN-999999990002");
        expect(() -> runAuth(auth, session(auth, s -> set(s, "cert", "value", b64(tbsFlip)))), ValidationReasons.CHAIN_UNTRUSTED);
        String sigFlip = flipB64(auth.optObj("session").optObj("cert").optString("value"), -1);
        expect(() -> runAuth(auth, session(auth, s -> set(s, "cert", "value", sigFlip))), ValidationReasons.CHAIN_UNTRUSTED);
        // The ACSP_V2 signature, and the signed payload (the stored RP challenge).
        String authSig = flipB64(auth.optObj("session").optObj("signature").optString("value"), 7);
        expect(() -> runAuth(auth, session(auth, s -> set(s, "signature", "value", authSig))), ValidationReasons.AUTH_SIGNATURE);
        Json.Obj acsp = auth.optObj("acsp");
        AcspContext a = ConformanceTest.acsp(acsp);
        AcspContext other = new AcspContext(flipB64(a.rpChallenge(), 0), a.relyingPartyName(), a.brokeredRpName(), a.interactions(),
            a.initialCallbackUrl(), a.flowTypes(), a.signatureAlgorithm(), a.hashAlgorithm());
        expect(() -> validator(auth).validateAuth(session(auth, s -> s), other), ValidationReasons.AUTH_SIGNATURE);
        // The RAW_DIGEST signature.
        Json.Obj sign = rpCase("sign-pss-sha256");
        String signSig = flipB64(sign.optObj("session").optObj("signature").optString("value"), 3);
        expect(() -> runSign(sign, session(sign, s -> set(s, "signature", "value", signSig))), ValidationReasons.SIGN_SIGNATURE);
    }

    @Test
    public void ocspFlippedSignature() {
        Json.Obj c = null;
        for (Object o : ConformanceTest.json("ocsp/cases.json").optArr("cases")) {
            if (((Json.Obj) o).optString("name").equals("good")) c = (Json.Obj) o;
        }
        Json.Obj http = c.optObj("http");
        Json.Obj rep = http.optObj(http.keySet().iterator().next());
        rep.values.set(rep.keys.indexOf("bodyB64"), flipB64(rep.optString("bodyB64"), -1));
        OcspRevocationChecker check = OcspRevocationChecker.builder().transport(ConformanceTest.replay(http, new ArrayList<>()))
            .clock(Clock.fixed(NOW, ZoneOffset.UTC)).build();
        try {
            check.check(ConformanceTest.cert(pki("leaf-auth.pem")), ConformanceTest.cert(pki("04-eid.pem")));
            fail();
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.SIGNATURE, e.kind());
        }
    }

    // ── SHOULD FIX 3: an empty verifier is compared, not ignored ──

    @Test
    public void emptyVerifierRejected() {
        Json.Obj auth = rpCase("auth-pss-sha512-qr");
        SessionResult r = session(auth, s -> s);
        AcspContext a = ConformanceTest.acsp(auth.optObj("acsp"));
        expect(() -> validator(auth).validateAuth(r, a, ValidateAuthOptions.builder().userChallengeVerifier("").build()),
            ValidationReasons.AUTH_VERIFIER_MISMATCH);
        Json.Obj w = rpCase("auth-web2app-verifier");
        expect(() -> validator(w).validateAuth(session(w, s -> s), ConformanceTest.acsp(w.optObj("acsp")), ValidateAuthOptions.builder()
            .expectedFlowType(FlowType.WEB2APP).userChallengeVerifier("").build()), ValidationReasons.AUTH_VERIFIER_REQUIRED);
        assertNotNull(validator(auth).validateAuth(r, a, ValidateAuthOptions.builder().userChallengeVerifier(null).build()));
    }

    // ── SHOULD FIX 7: hand-built records with nulls → Validation, never NullPointerException ──

    @Test
    public void nullsAreValidationErrors() {
        Json.Obj auth = rpCase("auth-pss-sha512-qr");
        ResponseValidator v = validator(auth);
        SessionResult empty = new SessionResult("COMPLETE", "OK", null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null);
        expect(() -> v.validateAuth(empty, ConformanceTest.acsp(auth.optObj("acsp"))), ValidationReasons.NO_CERTIFICATE);
        expect(() -> v.validateSign(empty, null), ValidationReasons.NO_CERTIFICATE);
        expect(() -> v.validateCertificateChoice(empty, null), ValidationReasons.NO_CERTIFICATE);
        try {
            v.validateAuth(new SessionResult("COMPLETE", null, null, null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null), ConformanceTest.acsp(auth.optObj("acsp")));
            fail();
        } catch (EidException.SessionFailed e) {
            assertEquals("UNKNOWN", e.endResult());
        }
        expect(() -> v.validateAuth(new SessionResult(null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null), null), ValidationReasons.AUTH_ACSP_MISSING);
        SessionResult real = session(auth, s -> s);
        AcspContext nulls = new AcspContext(null, null, null, null, null, null, null, null);
        expect(() -> v.validateAuth(real, nulls), ValidationReasons.AUTH_FLOW_NOT_OFFERED);
        SessionResult noParams = new SessionResult(real.state(), real.endResult(), real.documentNumber(), real.certificateDerB64(),
            real.certificateLevel(), real.signatureValueB64(), real.signatureAlgorithm(), real.signatureProtocol(), real.serverRandom(),
            real.userChallenge(), real.flowType(), real.initialCallbackUrl(), new SignatureAlgorithmParameters(null, null, null, null, null),
            real.interactionTypeUsed(), null, null, null, null, null);
        expect(() -> v.validateAuth(noParams, ConformanceTest.acsp(auth.optObj("acsp"))), ValidationReasons.ALG_UNSUPPORTED);
        expect(() -> ResponseValidator.certificateLevelOf((X509Certificate) null, ResponseValidator.PROTOCOL_ACSP_V2), ValidationReasons.CERT_MALFORMED);
        try {
            new ResponseValidator(TrustConfig.builder().trustAnchorsPem((String) null).build());
            fail();
        } catch (IllegalArgumentException expected) {
            // a configuration error, not an NPE
        }
        assertEquals(RevocationOutcome.UNCHECKED, v.checkRevocationWith(null, OcspRevocationChecker.create(), RevocationMode.SOFT_FAIL));
    }
}
