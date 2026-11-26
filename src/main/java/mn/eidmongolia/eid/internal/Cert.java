package mn.eidmongolia.eid.internal;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * X.509 certificate with the raw DER fields the Go reference compares byte-wise (RawIssuer, RawSubject, serial, SPKI) —
 * parsed here, never re-encoded by the platform. Crypto goes through `java.security`.
 */
public final class Cert {
    public static final String OID_AIA = "1.3.6.1.5.5.7.1.1";
    public static final String OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";
    public static final String OID_CRL_DP = "2.5.29.31";
    public static final String OID_EKU = "2.5.29.37";
    public static final String OID_ANY_EKU = "2.5.29.37.0";
    public static final String OID_SERIAL_NUMBER = "2.5.4.5";
    public static final String OID_COMMON_NAME = "2.5.4.3";
    public static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    public static final String OID_SKI = "2.5.29.14";
    public static final String OID_AKI = "2.5.29.35";
    /** X509Certificate.getKeyUsage() indices. */
    public static final int KU_CERT_SIGN = 5;
    public static final int KU_CRL_SIGN = 6;
    public static final String OID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
    public static final String OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    private static final class Ext {
        final String oid;
        final boolean critical;
        final byte[] value;

        Ext(String oid, boolean critical, byte[] value) {
            this.oid = oid;
            this.critical = critical;
            this.value = value;
        }
    }

    public final byte[] raw;
    public final X509Certificate x509;
    public final byte[] rawIssuer;
    public final byte[] rawSubject;
    public final BigInteger serial;
    /** SubjectPublicKeyInfo.subjectPublicKey BIT STRING contents without the unused-bits byte (OCSP issuerKeyHash). */
    public final byte[] publicKeyBits;
    /** The SubjectPublicKeyInfo element as encoded (Go {@code RawSubjectPublicKeyInfo}). */
    public final byte[] rawSubjectPublicKeyInfo;
    private final List<Ext> extensions = new ArrayList<>();
    private final List<String[]> subjectAttrs;
    private final List<String[]> issuerAttrs;

    private Cert(byte[] raw, X509Certificate x509) {
        this.raw = raw;
        this.x509 = x509;
        List<Der.Tlv> f = Der.parse(raw).child(0).children();
        int i = f.get(0).tag == Der.ctx(0) ? 1 : 0; // [0] version
        serial = f.get(i++).bigInt();
        i++; // signature AlgorithmIdentifier
        rawIssuer = f.get(i++).encoded();
        i++; // validity
        Der.Tlv subject = f.get(i++);
        rawSubject = subject.encoded();
        Der.Tlv spki = f.get(i++);
        rawSubjectPublicKeyInfo = spki.encoded();
        Der.Tlv bits = spki.child(1);
        publicKeyBits = Arrays.copyOfRange(bits.buf, bits.valueStart + 1, bits.end);
        for (int k = i; k < f.size(); k++) {
            if (f.get(k).tag != Der.ctx(3)) continue;
            for (Der.Tlv e : f.get(k).child(0).children()) {
                List<Der.Tlv> c = e.children();
                boolean critical = c.size() == 3 && c.get(1).tag == Der.BOOLEAN && c.get(1).value()[0] != 0;
                extensions.add(new Ext(c.get(0).oid(), critical, c.get(c.size() - 1).value()));
            }
            break;
        }
        subjectAttrs = nameAttrs(subject);
        issuerAttrs = nameAttrs(Der.parse(rawIssuer));
    }

    /**
     * THE certificate entry point of the SDK (every package): DER only. The JDK parser and the hand parser above must
     * read the SAME bytes — the JDK factory reads PEM (skipping any leading bytes up to "-----BEGIN") whenever the first
     * byte is not 0x30, so a crafted input could show the JDK one certificate (signature, key, validity) and the hand
     * parser another (subject, extensions). Hence: first byte 0x30 (SEQUENCE), the JDK's re-encoding byte-identical to
     * the input (no BER, no non-minimal lengths, no trailing bytes — Go x509.ParseCertificate), and the hand-parsed
     * serial, issuer, subject and extension sets equal to the JDK's.
     *
     * @throws IllegalArgumentException anything else
     */
    public static Cert parse(byte[] der) {
        if (der == null || der.length == 0 || (der[0] & 0xff) != Der.SEQUENCE) {
            throw new IllegalArgumentException("certificate: not a DER SEQUENCE");
        }
        X509Certificate x;
        try {
            x = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
            if (!Arrays.equals(x.getEncoded(), der)) throw new IllegalArgumentException("certificate: not DER or trailing data");
        } catch (java.security.cert.CertificateException e) {
            throw new IllegalArgumentException("certificate: " + e.getMessage(), e);
        }
        Cert c;
        try {
            Der.Tlv t = Der.parse(der);
            if (t.tag != Der.SEQUENCE || t.end != der.length) throw new IllegalArgumentException("trailing data after certificate");
            c = new Cert(der.clone(), x);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("certificate: " + e.getMessage(), e);
        }
        c.crossCheck();
        return c;
    }

    /** The hand-parsed fields equal the JDK's (defence in depth on top of the byte-identity check). */
    private void crossCheck() {
        if (!serial.equals(x509.getSerialNumber())
            || !Arrays.equals(rawIssuer, x509.getIssuerX500Principal().getEncoded())
            || !Arrays.equals(rawSubject, x509.getSubjectX500Principal().getEncoded())) {
            throw new IllegalArgumentException("certificate: serial / issuer / subject differ between parsers");
        }
        Set<String> crit = new HashSet<>();
        Set<String> all = new HashSet<>();
        for (Ext e : extensions) {
            if (!all.add(e.oid)) throw new IllegalArgumentException("certificate: duplicate extension " + e.oid);
            if (e.critical) crit.add(e.oid);
        }
        Set<String> jdkCrit = x509.getCriticalExtensionOIDs() == null ? Set.of() : x509.getCriticalExtensionOIDs();
        Set<String> jdkAll = new HashSet<>(jdkCrit);
        if (x509.getNonCriticalExtensionOIDs() != null) jdkAll.addAll(x509.getNonCriticalExtensionOIDs());
        if (!crit.equals(jdkCrit) || !all.equals(jdkAll)) throw new IllegalArgumentException("certificate: extensions differ between parsers");
    }

    /** The RSA modulus size in bits; 0 for a non-RSA key. */
    public int rsaBits() {
        PublicKey k = publicKey();
        return k instanceof RSAPublicKey ? ((RSAPublicKey) k).getModulus().bitLength() : 0;
    }

    private static final Set<String> STRONG_SIG_OIDS = Set.of(
        "1.2.840.113549.1.1.11", // sha256WithRSAEncryption
        "1.2.840.113549.1.1.12", // sha384WithRSAEncryption
        "1.2.840.113549.1.1.13", // sha512WithRSAEncryption
        "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
        "1.2.840.10045.4.3.3", // ecdsa-with-SHA384
        "1.2.840.10045.4.3.4"); // ecdsa-with-SHA512
    private static final String OID_RSASSA_PSS = "1.2.840.113549.1.1.10";
    /** SHA-1 signatures — accepted only where the references accept them (x/crypto/ocsp embedded responder check). */
    private static final Set<String> SHA1_SIG_OIDS = Set.of("1.2.840.113549.1.1.5", "1.2.840.10045.4.1");

    /**
     * This certificate's signature algorithm is one a chain may use (Go x509 {@code CheckSignatureFrom}): RSA PKCS#1
     * v1.5 / ECDSA with SHA-256/384/512, or RSASSA-PSS with SHA-256/384/512, MGF1 of the same hash, salt = hash length,
     * trailer 1. SHA-1, MD5, MD2 → false.
     */
    public boolean strongSignatureAlgorithm() {
        String oid = x509.getSigAlgOID();
        if (STRONG_SIG_OIDS.contains(oid)) return true;
        if (!OID_RSASSA_PSS.equals(oid)) return false;
        try {
            java.security.AlgorithmParameters ap = java.security.AlgorithmParameters.getInstance("RSASSA-PSS");
            ap.init(x509.getSigAlgParams());
            java.security.spec.PSSParameterSpec p = ap.getParameterSpec(java.security.spec.PSSParameterSpec.class);
            String h = p.getDigestAlgorithm();
            int hLen = "SHA-256".equals(h) ? 32 : "SHA-384".equals(h) ? 48 : "SHA-512".equals(h) ? 64 : 0;
            return hLen > 0 && "MGF1".equalsIgnoreCase(p.getMGFAlgorithm())
                && p.getMGFParameters() instanceof java.security.spec.MGF1ParameterSpec
                && h.equals(((java.security.spec.MGF1ParameterSpec) p.getMGFParameters()).getDigestAlgorithm())
                && p.getSaltLength() == hLen && p.getTrailerField() == 1;
        } catch (Exception e) {
            return false;
        }
    }

    private static final Pattern PEM = Pattern.compile("-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----");

    /** PEM CERTIFICATE blocks → DER (resources / test fixtures). */
    public static List<byte[]> pemBlocks(String pem) {
        List<byte[]> out = new ArrayList<>();
        Matcher m = PEM.matcher(pem);
        while (m.find()) out.add(Text.unbase64(m.group(1)));
        return out;
    }

    public static byte[] pemSingle(byte[] pemAscii) {
        List<byte[]> b = pemBlocks(new String(pemAscii, StandardCharsets.US_ASCII));
        if (b.size() != 1) throw new IllegalArgumentException("expected one PEM certificate");
        return b.get(0);
    }

    public PublicKey publicKey() {
        return x509.getPublicKey();
    }

    public boolean isRsa() {
        return publicKey() instanceof RSAPublicKey;
    }

    public boolean isEc() {
        return publicKey() instanceof ECPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof Cert && Arrays.equals(raw, ((Cert) o).raw);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(raw);
    }

    /**
     * A CHAIN signature: {@link #strongSignatureAlgorithm()} and it verifies with [issuer]'s key (Go
     * {@code CheckSignatureFrom}'s signature part — no CA checks; see [issuedBy]).
     */
    public boolean signedBy(Cert issuer) {
        return strongSignatureAlgorithm() && verifiesWith(issuer);
    }

    /**
     * x/crypto/ocsp's embedded-responder check ({@code issuer.CheckSignature}, which still allows SHA-1): a strong
     * algorithm or SHA-1 (RSA / ECDSA), never MD5 / MD2, verifying with [issuer]'s key.
     */
    public boolean signedByAllowingSha1(Cert issuer) {
        return (strongSignatureAlgorithm() || SHA1_SIG_OIDS.contains(x509.getSigAlgOID())) && verifiesWith(issuer);
    }

    private boolean verifiesWith(Cert issuer) {
        try {
            x509.verify(issuer.publicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Go {@code bytes.Equal(c.RawIssuer, issuer.RawSubject) && c.CheckSignatureFrom(issuer) == nil}: the issuer must be a CA
     * allowed to sign certificates (basicConstraints cA, keyUsage keyCertSign when present).
     */
    public boolean issuedBy(Cert issuer) {
        return Arrays.equals(rawIssuer, issuer.rawSubject) && issuer.mayIssue(KU_CERT_SIGN) && signedBy(issuer);
    }

    /** basicConstraints extension present (Go `BasicConstraintsValid`). */
    public boolean basicConstraintsValid() {
        return extension(OID_BASIC_CONSTRAINTS) != null;
    }

    /** basicConstraints cA = true. */
    public boolean isCa() {
        return basicConstraintsValid() && x509.getBasicConstraints() >= 0;
    }

    /** pathLenConstraint; null = no limit (Go `MaxPathLen` -1). */
    public Integer maxPathLen() {
        int v = x509.getBasicConstraints();
        return isCa() && v != Integer.MAX_VALUE ? v : null;
    }

    /**
     * Go `CheckSignatureFrom` / `RevocationList.CheckSignatureFrom` parent checks: a v3 certificate needs basicConstraints
     * with cA = true (v1/v2 without the extension are accepted, like Go); a non-empty keyUsage must include [usageBit].
     */
    public boolean mayIssue(int usageBit) {
        if (x509.getVersion() == 3 && !basicConstraintsValid() || basicConstraintsValid() && !isCa()) return false;
        boolean[] ku = x509.getKeyUsage();
        if (ku == null) return true;
        boolean any = false;
        for (boolean b : ku) any |= b;
        return !any || (usageBit < ku.length && ku[usageBit]);
    }

    /** Go `Verify` path-length rule: [intermediates] CA certificates below this one in the chain. */
    public boolean allowsPath(int intermediates) {
        Integer m = maxPathLen();
        return m == null || intermediates <= m;
    }

    public boolean validAt(Date at) {
        return !at.before(x509.getNotBefore()) && !at.after(x509.getNotAfter());
    }

    /** SubjectKeyIdentifier (empty if absent). */
    public byte[] subjectKeyId() {
        byte[] v = extensionValue(OID_SKI);
        return v == null ? new byte[0] : Der.parse(v).value();
    }

    /** Errors name certificates by serial (Go `SerialNumber.Text(16)`), never by CN — the citizen's name is PII. */
    public String serialRef() {
        return "serial " + serial.toString(16);
    }

    private Ext extension(String oid) {
        for (Ext e : extensions) if (e.oid.equals(oid)) return e;
        return null;
    }

    /** The extension's extnValue contents, or null. */
    public byte[] extensionValue(String oid) {
        Ext e = extension(oid);
        return e == null ? null : e.value;
    }

    public int extensionCount(String oid) {
        int n = 0;
        for (Ext e : extensions) if (e.oid.equals(oid)) n++;
        return n;
    }

    public static final String OID_NAME_CONSTRAINTS = "2.5.29.30";
    /**
     * The critical extensions the SDK understands (TS validator.ts HANDLED_CRITICAL, Go handledCritical); any other
     * critical extension fails a chain (fail-closed).
     */
    public static final Set<String> HANDLED_CRITICAL = Set.of(
        "2.5.29.14", // subjectKeyIdentifier
        "2.5.29.15", // keyUsage
        "2.5.29.17", // subjectAltName
        "2.5.29.19", // basicConstraints
        "2.5.29.30", // nameConstraints (on a CA rejected separately)
        "2.5.29.31", // cRLDistributionPoints
        "2.5.29.32", // certificatePolicies
        "2.5.29.35", // authorityKeyIdentifier
        "2.5.29.37", // extKeyUsage
        "1.3.6.1.5.5.7.1.1"); // authorityInfoAccess

    /** A critical extension outside {@link #HANDLED_CRITICAL}. */
    public boolean hasUnhandledCritical() {
        for (Ext e : extensions) if (e.critical && !HANDLED_CRITICAL.contains(e.oid)) return true;
        return false;
    }

    /** OIDs of the extensions marked critical, in certificate order. */
    public List<String> criticalExtensionOids() {
        List<String> out = new ArrayList<>();
        for (Ext e : extensions) if (e.critical) out.add(e.oid);
        return out;
    }

    /** AuthorityKeyIdentifier keyIdentifier [0] (empty if absent). */
    public byte[] authorityKeyId() {
        byte[] v = extensionValue(OID_AKI);
        if (v == null) return new byte[0];
        for (Der.Tlv k : Der.parse(v).children()) {
            if (k.tag == Der.ctx(0, false)) return k.value();
        }
        return new byte[0];
    }

    /** certificatePolicies (2.5.29.32) policyIdentifier OIDs, in order (empty if absent). */
    public List<String> policyIdentifiers() {
        byte[] v = extensionValue("2.5.29.32");
        if (v == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        for (Der.Tlv pi : Der.parse(v).children()) out.add(pi.child(0).oid());
        return out;
    }

    /** AIA id-ad-ocsp URIs, in order (Go `OCSPServer`). */
    public List<String> ocspServers() {
        byte[] v = extensionValue(OID_AIA);
        if (v == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        for (Der.Tlv ad : Der.parse(v).children()) {
            if (ad.child(0).oid().equals(OID_AD_OCSP) && ad.child(1).tag == 0x86) {
                out.add(new String(ad.child(1).value(), StandardCharsets.ISO_8859_1));
            }
        }
        return out;
    }

    /** CRL distribution point fullName URIs, in order (Go `CRLDistributionPoints`). */
    public List<String> crlDistributionPoints() {
        byte[] v = extensionValue(OID_CRL_DP);
        if (v == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        for (Der.Tlv dp : Der.parse(v).children()) {
            Der.Tlv name = first(dp.children(), Der.ctx(0)); // distributionPoint
            if (name == null) continue;
            Der.Tlv full = first(name.children(), Der.ctx(0)); // fullName
            if (full == null) continue;
            for (Der.Tlv gn : full.children()) {
                if (gn.tag == 0x86) out.add(new String(gn.value(), StandardCharsets.ISO_8859_1));
            }
        }
        return out;
    }

    private static Der.Tlv first(List<Der.Tlv> l, int tag) {
        for (Der.Tlv t : l) if (t.tag == tag) return t;
        return null;
    }

    /** ExtendedKeyUsage OIDs (empty if absent). */
    public List<String> extKeyUsage() {
        byte[] v = extensionValue(OID_EKU);
        if (v == null) return Collections.emptyList();
        List<String> out = new ArrayList<>();
        for (Der.Tlv t : Der.parse(v).children()) out.add(t.oid());
        return out;
    }

    /** Go eidcrypto.IsTSASigningCert: exactly one EKU extension, critical, = {timeStamping}. */
    public boolean isTsaSigningCert() {
        if (extensionCount(OID_EKU) != 1) return false;
        Ext e = extension(OID_EKU);
        List<String> oids = new ArrayList<>();
        try {
            for (Der.Tlv t : Der.parse(e.value).children()) oids.add(t.oid());
        } catch (Exception x) {
            return false;
        }
        return e.critical && oids.equals(Collections.singletonList(OID_KP_TIMESTAMPING));
    }

    /** Go core.SignerDisplayName: GIVENNAME SURNAME (last of each wins), else CN. */
    public String displayName() {
        String given = lastAttr(subjectAttrs, "2.5.4.42");
        String sur = lastAttr(subjectAttrs, "2.5.4.4");
        String n = Text.trimSpace((given == null ? "" : given) + " " + (sur == null ? "" : sur));
        return n.isEmpty() ? commonName() : n;
    }

    public String commonName() {
        String v = lastAttr(subjectAttrs, "2.5.4.3");
        return v == null ? "" : v;
    }

    /** Subject attribute (last occurrence wins, like Go pkix.Name). */
    public String subjectAttr(String oid) {
        return lastAttr(subjectAttrs, oid);
    }

    /** How many times the subject carries the attribute (every RDN, multi-valued ones too). */
    public int subjectAttrCount(String oid) {
        int n = 0;
        for (String[] a : subjectAttrs) if (a[0].equals(oid)) n++;
        return n;
    }

    /** Subject attribute, first occurrence (Go pkix.Name Country[0], Names scan), or null. */
    public String subjectAttrFirst(String oid) {
        for (String[] a : subjectAttrs) if (a[0].equals(oid)) return a[1];
        return null;
    }

    /** Go `cert.Issuer.CommonName`. */
    public String issuerCommonName() {
        String v = lastAttr(issuerAttrs, "2.5.4.3");
        return v == null ? "" : v;
    }

    private static String lastAttr(List<String[]> attrs, String oid) {
        String v = null;
        for (String[] a : attrs) if (a[0].equals(oid)) v = a[1];
        return v;
    }

    private static List<String[]> nameAttrs(Der.Tlv name) {
        List<String[]> attrs = new ArrayList<>();
        for (Der.Tlv rdn : name.children()) {
            for (Der.Tlv atv : rdn.children()) {
                List<Der.Tlv> a = atv.children();
                attrs.add(new String[] {a.get(0).oid(), Text.asn1(a.get(1))});
            }
        }
        return attrs;
    }
}
