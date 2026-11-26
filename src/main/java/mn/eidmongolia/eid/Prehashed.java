package mn.eidmongolia.eid;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Base64;
import mn.eidmongolia.eid.internal.Sig;

/**
 * Signature verification over a ready digest (Go validator.go {@code VerifyPrehashedSignature}; TS validator.ts
 * {@code verifyPrehashedSignature}). JCA has no prehashed RSASSA-PSS, so EMSA-PSS-VERIFY (RFC 8017 §9.1.2) is ported from
 * TS {@code emsaPssVerify} / {@code mgf1} over the raw RSA public operation ({@link BigInteger#modPow}); PKCS#1 v1.5 is
 * NONEwithRSA over DigestInfo ‖ digest; ECDSA P-256 is NONEwithECDSA over the ASN.1 DER (r, s) signature.
 */
final class Prehashed {
    private Prehashed() {
    }

    /** PKCS#1 v1.5 DigestInfo DER prefixes (RFC 8017 §9.2), the NULL-parameter form Go and TS use. */
    private static byte[] digestInfo(String hash) {
        switch (hash) {
            case "SHA-256":
                return hex("3031300d060960864801650304020105000420");
            case "SHA-384":
                return hex("3041300d060960864801650304020205000430");
            case "SHA-512":
                return hex("3051300d060960864801650304020305000440");
            default:
                return null;
        }
    }

    private static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    /** SHA-256 / SHA-384 / SHA-512 length; 0 for anything else (Go {@code cryptoHash}). */
    static int hashLen(String hash) {
        if (hash == null) return 0;
        switch (hash) {
            case "SHA-256":
                return 32;
            case "SHA-384":
                return 48;
            case "SHA-512":
                return 64;
            default:
                return 0;
        }
    }

    private static final BigInteger P256_P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger P256_N = new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16);
    private static final BigInteger P256_B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger P256_GX = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);

    /** The key is on NIST P-256 (Go {@code k.Curve == elliptic.P256()}). */
    static boolean isP256(PublicKey pub) {
        if (!(pub instanceof ECPublicKey)) return false;
        ECParameterSpec p = ((ECPublicKey) pub).getParams();
        if (p == null) return false;
        ECField f = p.getCurve().getField();
        return f instanceof ECFieldFp && ((ECFieldFp) f).getP().equals(P256_P) && p.getOrder().equals(P256_N)
            && p.getCurve().getB().equals(P256_B) && p.getGenerator().getAffineX().equals(P256_GX) && p.getCofactor() == 1;
    }

    /**
     * Go {@code VerifyPrehashedSignature}: rsassa-pss (salt = hLen), shaNNNWithRSAEncryption (PKCS#1 v1.5),
     * ecdsa-with-SHA256 (P-256, SHA-256, ASN.1 DER). A key type that does not fit the algorithm → false.
     */
    static boolean verify(byte[] digest, String sigB64, PublicKey pub, String alg, String hash) {
        byte[] sig;
        try {
            sig = Base64.getDecoder().decode(sigB64 == null ? "" : sigB64);
        } catch (IllegalArgumentException e) {
            return false;
        }
        int hLen = hashLen(hash);
        if (sig.length == 0 || hLen == 0 || digest == null || digest.length != hLen || alg == null) return false;
        if (pub instanceof RSAPublicKey) {
            RSAPublicKey k = (RSAPublicKey) pub;
            // RSA floor (as EidQr.MIN_RSA_BITS): a smaller modulus never verifies.
            if (k.getModulus().bitLength() < ResponseValidator.MIN_RSA_BITS) return false;
            if (alg.equals(SignatureAlgorithm.RSASSA_PSS.wireName())) return rsaPssVerify(k, digest, sig, hash);
            if (alg.startsWith("sha") && alg.endsWith("WithRSAEncryption")) return pkcs1v15Verify(k, digest, sig, hash);
        } else if (pub instanceof ECPublicKey) {
            if (alg.equals(SignatureAlgorithm.ECDSA_WITH_SHA256.wireName()) && hash.equals("SHA-256") && isP256(pub)) {
                return jca("NONEwithECDSA", pub, digest, sig);
            }
        }
        return false;
    }

    /** RSASSA-PKCS1-v1_5 over [digest]: k-byte signature, NONEwithRSA over DigestInfo ‖ digest (Go rsa.VerifyPKCS1v15). */
    private static boolean pkcs1v15Verify(RSAPublicKey k, byte[] digest, byte[] sig, String hash) {
        byte[] prefix = digestInfo(hash);
        if (prefix == null || sig.length != (k.getModulus().bitLength() + 7) / 8) return false;
        byte[] t = new byte[prefix.length + digest.length];
        System.arraycopy(prefix, 0, t, 0, prefix.length);
        System.arraycopy(digest, 0, t, prefix.length, digest.length);
        return jca("NONEwithRSA", k, t, sig);
    }

    /** The JCA check via {@link Sig#verify} (ECDSA: 0 < r, s < n before the JDK sees the signature). */
    private static boolean jca(String alg, PublicKey pub, byte[] data, byte[] sig) {
        return Sig.verify(alg, pub, data, sig);
    }

    /**
     * RSASSA-PSS-VERIFY with sLen = hLen over a digest (Go {@code rsa.VerifyPSS} with SaltLength = hash size; TS
     * validator.ts verifyPrehashedSignature): the signature is exactly k bytes and &lt; n, m = s^e mod n, EM = I2OSP(m, k).
     */
    static boolean rsaPssVerify(RSAPublicKey k, byte[] mHash, byte[] sig, String hash) {
        BigInteger n = k.getModulus();
        int modBits = n.bitLength();
        int kLen = (modBits + 7) / 8;
        if (modBits == 0 || sig.length != kLen) return false;
        BigInteger s = new BigInteger(1, sig);
        if (s.compareTo(n) >= 0) return false;
        byte[] m = s.modPow(k.getPublicExponent(), n).toByteArray();
        byte[] em = new byte[kLen];
        int skip = m.length > kLen ? m.length - kLen : 0; // toByteArray's sign byte
        System.arraycopy(m, skip, em, kLen - (m.length - skip), m.length - skip);
        return emsaPssVerify(mHash, em, modBits - 1, hash);
    }

    /** MGF1 (RFC 8017 §B.2.1) — TS validator.ts {@code mgf1}. */
    static byte[] mgf1(String hash, byte[] seed, int length) {
        byte[] out = new byte[length];
        int n = 0;
        for (int i = 0; n < length; i++) {
            MessageDigest md = md(hash);
            md.update(seed);
            md.update(new byte[] {(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i});
            byte[] h = md.digest();
            int c = Math.min(h.length, length - n);
            System.arraycopy(h, 0, out, n, c);
            n += c;
        }
        return out;
    }

    /** EMSA-PSS-VERIFY (RFC 8017 §9.1.2), sLen = hLen — TS validator.ts {@code emsaPssVerify}. em may be k bytes (leading 0). */
    static boolean emsaPssVerify(byte[] mHash, byte[] em, int emBits, String hash) {
        int hLen = hashLen(hash);
        if (hLen == 0) return false;
        int sLen = hLen;
        int emLen = (emBits + 7) / 8;
        if (em.length > emLen) {
            for (int i = 0; i < em.length - emLen; i++) if (em[i] != 0) return false;
            em = Arrays.copyOfRange(em, em.length - emLen, em.length);
        }
        if (em.length < emLen || emLen < hLen + sLen + 2 || (em[emLen - 1] & 0xff) != 0xbc) return false;
        byte[] db = Arrays.copyOfRange(em, 0, emLen - hLen - 1); // maskedDB
        byte[] h = Arrays.copyOfRange(em, emLen - hLen - 1, emLen - 1);
        int topBits = 8 * emLen - emBits;
        if (topBits > 0 && ((db[0] & 0xff) >> (8 - topBits)) != 0) return false;
        byte[] mask = mgf1(hash, h, db.length);
        for (int i = 0; i < db.length; i++) db[i] ^= mask[i];
        if (topBits > 0) db[0] &= (byte) (0xff >> topBits);
        int psLen = emLen - hLen - sLen - 2;
        for (int i = 0; i < psLen; i++) if (db[i] != 0) return false;
        if (db[psLen] != 0x01) return false;
        byte[] salt = Arrays.copyOfRange(db, psLen + 1, db.length);
        MessageDigest md = md(hash);
        md.update(new byte[8]);
        md.update(mHash);
        md.update(salt);
        return MessageDigest.isEqual(h, md.digest());
    }

    private static MessageDigest md(String name) {
        try {
            return MessageDigest.getInstance(name);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(name, e);
        }
    }
}
