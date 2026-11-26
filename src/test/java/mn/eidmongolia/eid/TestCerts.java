package mn.eidmongolia.eid;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import mn.eidmongolia.eid.internal.Der;

/**
 * A flexible DER certificate / CSR builder for the RP service tests (Go tests' {@code x509.CreateCertificate} /
 * {@code CreateCertificateRequest} with a template). TEST ONLY — generated keys, "TEST ONLY …" organisation names.
 */
final class TestCerts {
    private TestCerts() {
    }

    static final int KU_DIGITAL_SIGNATURE = 0x80;
    static final int KU_NON_REPUDIATION = 0x40;
    static final int KU_KEY_ENCIPHERMENT = 0x20;
    static final int KU_CERT_SIGN = 0x04;
    static final int KU_CRL_SIGN = 0x02;
    static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    static final String EKU_EMAIL = "1.3.6.1.5.5.7.3.4";

    static KeyPair ec() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** One certificate's template. */
    static final class Spec {
        final List<String[]> subject = new ArrayList<>();
        byte[] issuerName;
        KeyPair key;
        PrivateKey signer;
        boolean ca;
        int ku = -1;
        List<String> eku;
        long serial = 1;
        String notBefore = "260101000000Z";
        String notAfter = "310101000000Z";

        Spec attr(String oid, String value) {
            subject.add(new String[] {oid, value});
            return this;
        }

        Spec cn(String v) {
            return attr("2.5.4.3", v);
        }

        byte[] name() {
            List<byte[]> rdns = new ArrayList<>();
            for (String[] a : subject) {
                int tag = "2.5.4.6".equals(a[0]) || "2.5.4.5".equals(a[0]) ? 0x13 : Der.UTF8_STRING;
                rdns.add(Der.set(Der.seq(Der.oid(a[0]), Der.tlv(tag, a[1].getBytes(StandardCharsets.UTF_8)))));
            }
            return Der.seq(rdns.toArray(new byte[0][]));
        }
    }

    private static byte[] ext(String oid, boolean critical, byte[] value) {
        return critical ? Der.seq(Der.oid(oid), Der.bool(true), Der.octets(value)) : Der.seq(Der.oid(oid), Der.octets(value));
    }

    private static byte[] ku(int bits) {
        return Der.tlv(Der.BIT_STRING, new byte[] {(byte) Integer.numberOfTrailingZeros(bits), (byte) bits});
    }

    private static byte[] alg(PrivateKey signer) {
        return signer.getAlgorithm().equals("EC") ? Der.seq(Der.oid("1.2.840.10045.4.3.2"))
            : Der.seq(Der.oid("1.2.840.113549.1.1.11"), Der.nullValue());
    }

    private static byte[] sign(PrivateKey signer, byte[] tbs) {
        try {
            Signature s = Signature.getInstance(signer.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA");
            s.initSign(signer);
            s.update(tbs);
            return s.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] bitString(byte[] b) {
        byte[] bits = new byte[b.length + 1];
        System.arraycopy(b, 0, bits, 1, b.length);
        return Der.tlv(Der.BIT_STRING, bits);
    }

    static byte[] cert(Spec s) {
        List<byte[]> exts = new ArrayList<>();
        if (s.ca) exts.add(ext("2.5.29.19", true, Der.seq(Der.bool(true))));
        if (s.ku >= 0) exts.add(ext("2.5.29.15", true, ku(s.ku)));
        if (s.eku != null) {
            List<byte[]> o = new ArrayList<>();
            for (String x : s.eku) o.add(Der.oid(x));
            exts.add(ext("2.5.29.37", false, Der.seq(o.toArray(new byte[0][]))));
        }
        PrivateKey signer = s.signer != null ? s.signer : s.key.getPrivate();
        byte[] a = alg(signer);
        byte[] validity = Der.seq(Der.tlv(0x17, s.notBefore.getBytes(StandardCharsets.US_ASCII)),
            Der.tlv(0x17, s.notAfter.getBytes(StandardCharsets.US_ASCII)));
        byte[] name = s.name();
        List<byte[]> tbsParts = new ArrayList<>(List.of(Der.tlv(Der.ctx(0), Der.integer(2)), Der.integer(BigInteger.valueOf(s.serial)), a,
            s.issuerName != null ? s.issuerName : name, validity, name, s.key.getPublic().getEncoded()));
        if (!exts.isEmpty()) tbsParts.add(Der.tlv(Der.ctx(3), Der.seq(exts.toArray(new byte[0][]))));
        byte[] tbs = Der.seq(tbsParts.toArray(new byte[0][]));
        return Der.seq(tbs, a, bitString(sign(signer, tbs)));
    }

    /** A PKCS#10 request (Go {@code x509.CreateCertificateRequest}): CN "ignored", empty attributes, self-signed. */
    static byte[] csr(KeyPair k) {
        byte[] cri = Der.seq(Der.integer(0), new Spec().cn("ignored").name(), k.getPublic().getEncoded(), Der.tlv(Der.ctx(0), new byte[0]));
        byte[] a = alg(k.getPrivate());
        return Der.seq(cri, a, bitString(sign(k.getPrivate(), cri)));
    }

    /** A CA + issued leaf pair for chain tests: root (self-signed CA, EC) and a leaf spec issued by it. */
    static final class Ca {
        final KeyPair key = ec();
        final Spec spec;
        final byte[] der;

        Ca(String cn) {
            spec = new Spec().attr("2.5.4.6", "MN").attr("2.5.4.10", "TEST ONLY eID").cn(cn);
            spec.key = key;
            spec.ca = true;
            spec.ku = KU_CERT_SIGN | KU_CRL_SIGN;
            spec.serial = 100;
            der = cert(spec);
        }

        /** A leaf template issued by this CA (the caller sets key / KU / EKU / subject). */
        Spec issue(KeyPair leafKey) {
            Spec s = new Spec();
            s.key = leafKey;
            s.signer = key.getPrivate();
            s.issuerName = spec.name();
            s.serial = 4242;
            return s;
        }

        String pem() {
            return TestPki.pem(der);
        }
    }
}
