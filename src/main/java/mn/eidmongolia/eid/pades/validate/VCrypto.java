package mn.eidmongolia.eid.pades.validate;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.List;
import java.util.Map;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Sig;

/**
 * Signature verification by AlgorithmIdentifier (TS x509.ts schemeFor + verifyWith) and digests. SDK hardening on top of
 * the reference: RSA keys below 2048 bits never verify, and an ECDSA (r, s) must be in range (Sig.ecdsaDerInRange)
 * before the JDK sees it.
 */
final class VCrypto {
    static final int MIN_RSA_BITS = 2048;

    static final String SHA1 = "1.3.14.3.2.26";
    static final String SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String SHA384 = "2.16.840.1.101.3.4.2.2";
    static final String SHA512 = "2.16.840.1.101.3.4.2.3";
    static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    static final String SHA256_RSA = "1.2.840.113549.1.1.11";
    static final String SHA384_RSA = "1.2.840.113549.1.1.12";
    static final String SHA512_RSA = "1.2.840.113549.1.1.13";
    static final String RSA_PSS = "1.2.840.113549.1.1.10";
    static final String ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    static final String ECDSA_SHA384 = "1.2.840.10045.4.3.3";
    static final String ECDSA_SHA512 = "1.2.840.10045.4.3.4";
    static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    static final String P256 = "1.2.840.10045.3.1.7";
    static final String P384 = "1.3.132.0.34";
    static final String P521 = "1.3.132.0.35";

    private static final Map<String, String> HASH_BY_OID = Map.of(SHA1, "SHA-1", SHA256, "SHA-256", SHA384, "SHA-384", SHA512, "SHA-512");

    private VCrypto() {
    }

    static byte[] digest(String name, byte[] data) {
        try {
            return MessageDigest.getInstance(name).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hashName(String oid) {
        return HASH_BY_OID.get(oid);
    }

    static final int MAX_RSA_BITS = 8192;

    /**
     * RSA: 2048 ≤ modulus ≤ 8192 bits and public exponent ≤ 2^32 − 1 (SDK floor, plus a CPU bound on hostile keys);
     * non-RSA keys pass.
     */
    static boolean keyStrongEnough(PublicKey k) {
        if (!(k instanceof RSAPublicKey)) return true;
        RSAPublicKey r = (RSAPublicKey) k;
        int bits = r.getModulus().bitLength();
        return bits >= MIN_RSA_BITS && bits <= MAX_RSA_BITS && r.getPublicExponent().bitLength() <= 32;
    }

    /**
     * TS verifySignature(pub, alg, data, sig): the scheme from the AlgorithmIdentifier [alg]; unsupported → exception
     * (callers treat it as false). Wrong key type → false.
     */
    static boolean verify(Cert pub, Asn1.Node alg, byte[] data, byte[] sig) {
        List<Asn1.Node> p = Asn1.children(alg);
        String o = Asn1.oid(Asn1.expect(Asn1.at(p, 0), Asn1.OID, "sigAlg"));
        PublicKey key = pub.publicKey();
        if (!keyStrongEnough(key)) return false;
        String jca;
        switch (o) {
            case "1.2.840.113549.1.1.5": jca = "SHA1withRSA"; break;
            case SHA256_RSA: jca = "SHA256withRSA"; break;
            case SHA384_RSA: jca = "SHA384withRSA"; break;
            case SHA512_RSA: jca = "SHA512withRSA"; break;
            case "1.2.840.10045.4.1": jca = "SHA1withECDSA"; break;
            case ECDSA_SHA256: jca = "SHA256withECDSA"; break;
            case ECDSA_SHA384: jca = "SHA384withECDSA"; break;
            case ECDSA_SHA512: jca = "SHA512withECDSA"; break;
            case RSA_PSS: {
                // Strict (SDK rule, as Cert.strongSignatureAlgorithm): SHA-256/384/512, MGF1 with the same hash, salt = hLen,
                // trailer 1. Anything else (absent params = SHA-1 defaults, other salts, other MGF hashes) does not verify.
                String hash = pssHash(p.size() > 1 ? p.get(1) : null);
                if (hash == null) return false;
                int salt = hash.equals("SHA-256") ? 32 : hash.equals("SHA-384") ? 48 : 64;
                if (!(key instanceof RSAPublicKey)) return false;
                try {
                    Signature s = Signature.getInstance("RSASSA-PSS");
                    s.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(hash), salt, 1));
                    s.initVerify(key);
                    s.update(data);
                    return s.verify(sig);
                } catch (Exception e) {
                    return false;
                }
            }
            default:
                throw new IllegalArgumentException("unsupported signature algorithm " + o);
        }
        if (jca.endsWith("withECDSA")) {
            if (!(key instanceof ECPublicKey) || !curveOk(pub)) return false;
        } else if (!(key instanceof RSAPublicKey)) {
            return false;
        }
        return Sig.verify(jca, key, data, sig);
    }

    /** RSASSA-PSS-params → the hash name when they are exactly {hash ∈ SHA-256/384/512, MGF1(same hash), salt = hLen,
     * trailer 1}; else null. */
    static String pssHash(Asn1.Node params) {
        try {
            if (params == null || params.tag != Asn1.SEQUENCE) return null;
            String hash = null;
            String mgfHash = null;
            long salt = 20;
            long trailer = 1;
            int last = -1;
            for (Asn1.Node f : Asn1.children(params)) {
                int t = f.tag;
                if (t < 0xa0 || t > 0xa3 || t <= last) return null;
                last = t;
                Asn1.Node inner = Asn1.children(f).get(0);
                if (t == 0xa0) hash = HASH_BY_OID.get(Asn1.oid(Asn1.children(inner).get(0)));
                if (t == 0xa1) {
                    List<Asn1.Node> m = Asn1.children(inner);
                    if (!Asn1.oid(m.get(0)).equals("1.2.840.113549.1.1.8") || m.size() != 2) return null;
                    mgfHash = HASH_BY_OID.get(Asn1.oid(Asn1.children(m.get(1)).get(0)));
                }
                if (t == 0xa2 || t == 0xa3) {
                    if (inner.tag != Asn1.INTEGER || inner.length() > 4) return null;
                    long v = Asn1.intValue(inner.value()).longValue();
                    if (t == 0xa2) salt = v;
                    else trailer = v;
                }
            }
            if (hash == null || hash.equals("SHA-1") || !hash.equals(mgfHash) || trailer != 1) return null;
            int hLen = hash.equals("SHA-256") ? 32 : hash.equals("SHA-384") ? 48 : 64;
            return salt == hLen ? hash : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** TS CURVES: P-256 / P-384 / P-521 only. */
    private static boolean curveOk(Cert c) {
        try {
            List<Asn1.Node> spki = Asn1.children(Asn1.readNode(c.rawSubjectPublicKeyInfo, 0));
            List<Asn1.Node> alg = Asn1.children(spki.get(0));
            if (!Asn1.oid(alg.get(0)).equals(EC_PUBLIC_KEY) || alg.size() < 2 || alg.get(1).tag != Asn1.OID) return false;
            String curve = Asn1.oid(alg.get(1));
            return curve.equals(P256) || curve.equals(P384) || curve.equals(P521);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Longest certificate serial (RFC 5280 §4.1.2.2: ≤ 20 octets). */
    static final int MAX_SERIAL_BITS = 159;

    /**
     * The validator's certificate entry point: {@link Cert#parse} (the SDK's single strict parser) plus the validator's
     * bounds — serial ≤ 20 octets, and every extension the validator reads (KU, EKU, AIA, CDP, basicConstraints) must
     * decode. Anything else → IllegalArgumentException, so a bad certificate fails only the signature that carries it.
     */
    static Cert cert(byte[] der) {
        Cert c = Cert.parse(der);
        if (c.serial.bitLength() > MAX_SERIAL_BITS) throw new IllegalArgumentException("certificate serial longer than 20 octets");
        try {
            c.extKeyUsage();
            c.ocspServers();
            c.crlDistributionPoints();
            c.x509.getKeyUsage();
            c.isCa();
            c.criticalExtensionOids();
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("certificate extension does not decode", e);
        }
        return c;
    }

    /** DER of an AlgorithmIdentifier SEQUENCE { oid } (TS algNode). */
    static Asn1.Node algNode(String oid) {
        byte[] o = mn.eidmongolia.eid.internal.Der.oid(oid);
        byte[] seq = mn.eidmongolia.eid.internal.Der.seq(o);
        return Asn1.parseOne(seq);
    }
}
