package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.junit.Test;

/**
 * The prehashed signature verifier (Go {@code VerifyPrehashedSignature}; RSA-PSS = the TS {@code emsaPssVerify} port)
 * against known-answer vectors from the conformance corpus (rp-validate cases signed by the Go generator), plus
 * mutations and a cross-check with JCA's message-level RSASSA-PSS.
 */
public class PrehashedTest {
    private static Json.Obj kase(String name) {
        for (Object o : ConformanceTest.json("rp-validate/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals(name)) return c;
        }
        throw new IllegalStateException(name);
    }

    private static SessionResult session(Json.Obj c) {
        return SessionService.parseSessionResult(FakeRp.text(c.get("session")));
    }

    private static PublicKey key(SessionResult r) {
        return ConformanceTest.cert(Base64.getDecoder().decode(r.certificateDerB64())).getPublicKey();
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    @Test
    public void rsaPssKnownAnswers() {
        for (String name : List.of("sign-pss-sha256", "sign-pss-sha512", "sign-qscd")) {
            Json.Obj c = kase(name);
            SessionResult r = session(c);
            assertEquals(name, "rsassa-pss", r.signatureAlgorithm());
            String hash = c.optString("hashAlgorithm");
            byte[] digest = Base64.getDecoder().decode(c.optString("digest"));
            byte[] sig = Base64.getDecoder().decode(r.signatureValueB64());
            PublicKey k = key(r);
            assertTrue(name, EidCrypto.verifyPrehashedSignature(digest, r.signatureValueB64(), k, "rsassa-pss", hash));
            // Any other digest, signature bit, length, hash or algorithm family fails.
            byte[] d2 = digest.clone();
            d2[0] ^= 1;
            assertFalse(name + " digest", EidCrypto.verifyPrehashedSignature(d2, r.signatureValueB64(), k, "rsassa-pss", hash));
            byte[] s2 = sig.clone();
            s2[s2.length - 1] ^= 1;
            assertFalse(name + " signature", EidCrypto.verifyPrehashedSignature(digest, b64(s2), k, "rsassa-pss", hash));
            assertFalse(name + " short", EidCrypto.verifyPrehashedSignature(digest, b64(Arrays.copyOf(sig, sig.length - 1)), k, "rsassa-pss", hash));
            byte[] big = ((RSAPublicKey) k).getModulus().toByteArray();
            byte[] n = Arrays.copyOfRange(big, big.length - sig.length, big.length); // s = n is not < n
            assertFalse(name + " s >= n", EidCrypto.verifyPrehashedSignature(digest, b64(n), k, "rsassa-pss", hash));
            assertFalse(name + " hash", EidCrypto.verifyPrehashedSignature(digest, r.signatureValueB64(), k, "rsassa-pss",
                hash.equals("SHA-256") ? "SHA-512" : "SHA-256"));
            assertFalse(name + " pkcs1", EidCrypto.verifyPrehashedSignature(digest, r.signatureValueB64(), k, "sha256WithRSAEncryption", hash));
            assertFalse(name + " base64", EidCrypto.verifyPrehashedSignature(digest, "!" + r.signatureValueB64(), k, "rsassa-pss", hash));
            assertFalse(name + " empty", EidCrypto.verifyPrehashedSignature(digest, "", k, "rsassa-pss", hash));
        }
    }

    /** EMSA-PSS-VERIFY on the encoded message itself: the trailer, the top bit, the padding and the salt are all checked. */
    @Test
    public void emsaPssEdges() {
        Json.Obj c = kase("sign-pss-sha256");
        SessionResult r = session(c);
        RSAPublicKey k = (RSAPublicKey) key(r);
        byte[] digest = Base64.getDecoder().decode(c.optString("digest"));
        BigInteger n = k.getModulus();
        int kLen = (n.bitLength() + 7) / 8;
        byte[] m = new BigInteger(1, Base64.getDecoder().decode(r.signatureValueB64())).modPow(k.getPublicExponent(), n).toByteArray();
        byte[] em = new byte[kLen];
        int skip = m.length > kLen ? 1 : 0;
        System.arraycopy(m, skip, em, kLen - (m.length - skip), m.length - skip);
        int emBits = n.bitLength() - 1;
        assertTrue(Prehashed.emsaPssVerify(digest, em, emBits, "SHA-256"));
        byte[] e1 = em.clone();
        e1[e1.length - 1] = (byte) 0xbb;
        assertFalse("trailer", Prehashed.emsaPssVerify(digest, e1, emBits, "SHA-256"));
        byte[] e2 = em.clone();
        e2[0] |= (byte) 0x80;
        assertFalse("top bit", Prehashed.emsaPssVerify(digest, e2, emBits, "SHA-256"));
        byte[] e3 = em.clone();
        e3[10] ^= 0x01; // inside the masked PS / salt
        assertFalse("db", Prehashed.emsaPssVerify(digest, e3, emBits, "SHA-256"));
        byte[] e4 = new byte[em.length + 1]; // a leading zero byte more is accepted, a non-zero one is not
        System.arraycopy(em, 0, e4, 1, em.length);
        assertTrue("leading zero", Prehashed.emsaPssVerify(digest, e4, emBits, "SHA-256"));
        e4[0] = 1;
        assertFalse("leading byte", Prehashed.emsaPssVerify(digest, e4, emBits, "SHA-256"));
        assertFalse("hash", Prehashed.emsaPssVerify(digest, em, emBits, "SHA-1"));
        // MGF1 (RFC 8017 B.2.1): the first block is H(seed || 00000000).
        byte[] seed = "seed".getBytes(StandardCharsets.US_ASCII);
        byte[] first = EidCrypto.digest("SHA-256", new byte[] {'s', 'e', 'e', 'd', 0, 0, 0, 0});
        assertTrue(Arrays.equals(first, Arrays.copyOf(Prehashed.mgf1("SHA-256", seed, 40), 32)));
        assertEquals(40, Prehashed.mgf1("SHA-256", seed, 40).length);
    }

    /** The ACSP_V2 auth vectors: the prehashed PSS verifier agrees with JCA's message-level RSASSA-PSS (salt = hLen). */
    @Test
    public void pssAgreesWithJca() throws Exception {
        int n = 0;
        for (Object o : ConformanceTest.json("rp-validate/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (!c.optString("kind").equals("auth") || c.optObj("expect").optObj("ok") == null) continue;
            SessionResult r = session(c);
            if (!r.signatureAlgorithm().equals("rsassa-pss")) continue;
            AcspContext a = ConformanceTest.acsp(c.optObj("acsp"));
            String hash = r.signatureAlgorithmParameters().hashAlgorithm();
            byte[] payload = Acsp.buildV2Payload(new AcspV2Params(null, r.serverRandom(), a.rpChallenge(), r.userChallenge(),
                a.relyingPartyName(), a.brokeredRpName(), a.interactions(), r.interactionTypeUsed(),
                ResponseValidator.signedCallbackUrl(r.initialCallbackUrl(), a.initialCallbackUrl(), r.flowType()), r.flowType()));
            PublicKey k = key(r);
            Signature jca = Signature.getInstance("RSASSA-PSS");
            jca.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), Prehashed.hashLen(hash), 1));
            jca.initVerify(k);
            jca.update(payload);
            byte[] sig = Base64.getDecoder().decode(r.signatureValueB64());
            assertTrue(c.optString("name") + " JCA", jca.verify(sig));
            assertTrue(c.optString("name"), EidCrypto.verifyPayloadSignature(payload, r.signatureValueB64(), k, "rsassa-pss", hash));
            payload[payload.length - 1] ^= 1;
            assertFalse(c.optString("name"), EidCrypto.verifyPayloadSignature(payload, r.signatureValueB64(), k, "rsassa-pss", hash));
            n++;
        }
        assertTrue("auth PSS vectors " + n, n >= 10);
    }

    @Test
    public void pkcs1AndEcdsaKnownAnswers() {
        Json.Obj c = kase("sign-pkcs1-sha384");
        SessionResult r = session(c);
        byte[] digest = Base64.getDecoder().decode(c.optString("digest"));
        PublicKey k = key(r);
        assertTrue(EidCrypto.verifyPrehashedSignature(digest, r.signatureValueB64(), k, "sha384WithRSAEncryption", "SHA-384"));
        assertFalse(EidCrypto.verifyPrehashedSignature(digest, r.signatureValueB64(), k, "rsassa-pss", "SHA-384"));
        byte[] d2 = digest.clone();
        d2[5] ^= 0x40;
        assertFalse(EidCrypto.verifyPrehashedSignature(d2, r.signatureValueB64(), k, "sha384WithRSAEncryption", "SHA-384"));

        Json.Obj e = kase("sign-ec-legacy");
        SessionResult er = session(e);
        byte[] ed = Base64.getDecoder().decode(e.optString("digest"));
        X509Certificate ec = ConformanceTest.cert(Base64.getDecoder().decode(er.certificateDerB64()));
        assertTrue(Prehashed.isP256(ec.getPublicKey()));
        assertTrue(EidCrypto.verifyPrehashedSignature(ed, er.signatureValueB64(), ec.getPublicKey(), "ecdsa-with-SHA256", "SHA-256"));
        assertFalse(EidCrypto.verifyPrehashedSignature(ed, er.signatureValueB64(), ec.getPublicKey(), "ecdsa-with-SHA256", "SHA-384"));
        assertFalse(EidCrypto.verifyPrehashedSignature(ed, er.signatureValueB64(), ec.getPublicKey(), "rsassa-pss", "SHA-256"));
        byte[] ed2 = ed.clone();
        ed2[31] ^= 1;
        assertFalse(EidCrypto.verifyPrehashedSignature(ed2, er.signatureValueB64(), ec.getPublicKey(), "ecdsa-with-SHA256", "SHA-256"));
        // ASN.1 DER only — the same (r, s) as IEEE P1363 r || s is rejected.
        byte[] der = Base64.getDecoder().decode(er.signatureValueB64());
        byte[] p1363 = p1363(der);
        assertFalse(EidCrypto.verifyPrehashedSignature(ed, b64(p1363), ec.getPublicKey(), "ecdsa-with-SHA256", "SHA-256"));
        assertFalse("RSA key", Prehashed.isP256(k));
    }

    private static byte[] p1363(byte[] der) {
        int i = 2;
        byte[] out = new byte[64];
        for (int part = 0; part < 2; part++) {
            int len = der[i + 1];
            byte[] v = Arrays.copyOfRange(der, i + 2, i + 2 + len);
            byte[] x = new BigInteger(1, v).toByteArray();
            int s = x.length > 32 ? x.length - 32 : 0;
            System.arraycopy(x, s, out, part * 32 + 32 - (x.length - s), x.length - s);
            i += 2 + len;
        }
        return out;
    }
}
