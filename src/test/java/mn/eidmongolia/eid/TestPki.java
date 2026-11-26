package mn.eidmongolia.eid;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import mn.eidmongolia.eid.internal.Der;

/**
 * A tiny DER certificate builder for negative tests that the conformance corpus does not cover (weak chain signature
 * algorithms, small CA keys) and the dual-parser wrapper. TEST ONLY — generated keys, names "TEST ONLY …".
 */
final class TestPki {
    private TestPki() {
    }

    static final String SHA256_RSA = "1.2.840.113549.1.1.11";
    static final String SHA1_RSA = "1.2.840.113549.1.1.5";

    static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(bits);
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] name(String cn) {
        return Der.seq(Der.set(Der.seq(Der.oid("2.5.4.3"), Der.tlv(Der.UTF8_STRING, cn.getBytes(StandardCharsets.UTF_8)))));
    }

    private static byte[] ext(String oid, boolean critical, byte[] value) {
        return critical ? Der.seq(Der.oid(oid), Der.bool(true), Der.octets(value)) : Der.seq(Der.oid(oid), Der.octets(value));
    }

    /** keyUsage BIT STRING with one content byte. */
    private static byte[] ku(int bits) {
        return Der.tlv(Der.BIT_STRING, new byte[] {(byte) Integer.numberOfTrailingZeros(bits), (byte) bits}); // DER: unused = trailing zeros
    }

    /**
     * A certificate: v3, the given names, validity 2026-01-01 … 2031-01-01, CA (keyCertSign + cRLSign, CA:TRUE) or a
     * signing leaf (nonRepudiation), signed by [signer] with [sigOid] (sha256WithRSA / sha1WithRSA).
     */
    static byte[] cert(String subjectCn, String issuerCn, KeyPair subject, PrivateKey signer, String sigOid, boolean ca, long serial) {
        List<byte[]> exts = new ArrayList<>();
        if (ca) {
            exts.add(ext("2.5.29.19", true, Der.seq(Der.bool(true))));
            exts.add(ext("2.5.29.15", true, ku(0x06)));
        } else {
            exts.add(ext("2.5.29.15", true, ku(0x40)));
        }
        byte[] alg = Der.seq(Der.oid(sigOid), Der.nullValue());
        byte[] validity = Der.seq(Der.tlv(0x17, "260101000000Z".getBytes(StandardCharsets.US_ASCII)),
            Der.tlv(0x17, "310101000000Z".getBytes(StandardCharsets.US_ASCII)));
        byte[] tbs = Der.seq(Der.tlv(Der.ctx(0), Der.integer(2)), Der.integer(BigInteger.valueOf(serial)), alg, name(issuerCn), validity,
            name(subjectCn), subject.getPublic().getEncoded(), Der.tlv(Der.ctx(3), Der.seq(exts.toArray(new byte[0][]))));
        String jca = SHA1_RSA.equals(sigOid) ? "SHA1withRSA" : "SHA256withRSA";
        try {
            Signature s = Signature.getInstance(jca);
            s.initSign(signer);
            s.update(tbs);
            byte[] sig = s.sign();
            byte[] bits = new byte[sig.length + 1];
            System.arraycopy(sig, 0, bits, 1, sig.length);
            return Der.seq(tbs, alg, Der.tlv(Der.BIT_STRING, bits));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String pem(byte[] der) {
        return "-----BEGIN CERTIFICATE-----\n" + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der)
            + "\n-----END CERTIFICATE-----\n";
    }

    /**
     * The dual-parser attack input (security review of PR #7): {@code 04 82 LL LL | fake TBS | 04 82 LL LL "\n-----BEGIN
     * CERTIFICATE-----\n" b64(real) "\n-----END CERTIFICATE-----\n"}. The JDK factory (first byte ≠ 0x30 → PEM mode)
     * sees [real]; a hand parser that walks child(0) sees [fakeTbs].
     */
    static byte[] dualParserWrapper(byte[] real, byte[] fakeTbs) {
        byte[] pemText = ("\n" + pem(real)).getBytes(StandardCharsets.US_ASCII);
        return Der.tlv(Der.OCTET_STRING, Der.concat(fakeTbs, Der.tlv(Der.OCTET_STRING, pemText)));
    }

    /** [real]'s TBS with every "PNOMN-999999990001" replaced by "PNOMN-999999990002" (another citizen; same length). */
    static byte[] victimTbs(byte[] real) {
        return replace(Der.parse(real).child(0).encoded(), "PNOMN-999999990001", "PNOMN-999999990002");
    }

    static byte[] replace(byte[] b, String from, String to) {
        byte[] f = from.getBytes(StandardCharsets.US_ASCII);
        byte[] t = to.getBytes(StandardCharsets.US_ASCII);
        byte[] out = b.clone();
        int n = 0;
        for (int i = 0; i + f.length <= out.length; i++) {
            boolean m = true;
            for (int k = 0; k < f.length && m; k++) m = out[i + k] == f[k];
            if (m) {
                System.arraycopy(t, 0, out, i, t.length);
                n++;
            }
        }
        if (n == 0) throw new IllegalStateException("not found: " + from);
        return out;
    }
}
