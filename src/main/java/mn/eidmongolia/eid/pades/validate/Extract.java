package mn.eidmongolia.eid.pades.validate;

import java.math.BigInteger;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;

/**
 * The extraction stage — TS src/pades/validate/extract.ts (Go pades/internal/validate/extract.go). No trust decisions:
 * facts from the document only (bytes, certificates, whether the cryptography matches).
 */
final class Extract {
    static final int MAX_PDF_BYTES = 10 << 20;
    static final int MAX_SIGNATURES = 16;
    private static final int MAX_DSS_ITEMS = 64;
    private static final int MAX_DSS_STREAM = 1 << 20;
    private static final long MAX_DSS_TOTAL = 8L << 20;
    static final int MAX_CMS_CERTS = 32;
    private static final int MAX_CLAIMED_ROLES = 4;
    private static final int MAX_CLAIMED_ROLE_RUNES = 900;

    private Extract() {
    }

    /** Extraction failure codes (TS ExtractError). */
    static final class Failure extends Exception {
        final String code;

        Failure(String code) {
            super(code);
            this.code = code;
        }
    }

    static final class RawTimestamp {
        Instant time = Asn1.ZERO;
        String serial = "";
        boolean matches;
        boolean weakDigest;
        byte[] tsaCert;
        final List<byte[]> certs = new ArrayList<>();
    }

    static final class RawDss {
        final List<byte[]> certs;
        final List<byte[]> ocsps;
        final List<byte[]> crls;

        RawDss(List<byte[]> certs, List<byte[]> ocsps, List<byte[]> crls) {
            this.certs = certs;
            this.ocsps = ocsps;
            this.crls = crls;
        }
    }

    static final class RawSignature {
        String signerName = "";
        String reason = "";
        String location = "";
        Instant claimedTime;
        boolean malformed;
        boolean integrity;
        boolean weakDigest;
        boolean coversWhole;
        boolean laterSignaturesOnly;
        int laterSignatures;
        boolean laterVisible;
        boolean visible;
        long signedEnd;
        int objNum;
        long[] byteRange;
        byte[] leaf;
        final List<byte[]> certs = new ArrayList<>();
        RawTimestamp timestamp;
        String subFilter = "";
        /** "" | "match" | "mismatch" */
        String signingCertV2 = "";
        boolean signingTimeAttr;
        List<String> claimedRoles = new ArrayList<>();
        String cmsSha256 = "";
        String messageDigest = "";
        RawDss dss;
    }

    static final class Extracted {
        final List<RawSignature> sigs;
        final Map<Integer, SigMeta> metas;
        final String docId;

        Extracted(List<RawSignature> sigs, Map<Integer, SigMeta> metas, String docId) {
            this.sigs = sigs;
            this.metas = metas;
            this.docId = docId;
        }
    }

    /** trailer / xref stream /Encrypt reference or direct dictionary (Go encryptRef). */
    private static final Pattern ENCRYPT_REF = Pattern.compile("/Encrypt(?:\\s+\\d+\\s+\\d+\\s+R|\\s*<<)");
    private static final Pattern UUID_RE = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    static final String AP_VERIFY_PREFIX = "https://ca.eidmongolia.mn/verify/";

    /** JS \s (ASCII subset relevant to latin1 text: also U+00A0 and U+0085? JS \s includes U+00A0 but not U+0085). */
    private static String latin1(byte[] b) {
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    private static boolean encryptRef(byte[] doc) {
        // JS \s on a latin1 string = [\t\n\v\f\r  ] (+ U+FEFF etc. not reachable in latin1).
        String s = latin1(doc);
        Matcher m = Pattern.compile("/Encrypt(?:[\\t\\n\\x0B\\f\\r \\u00a0]+\\d+[\\t\\n\\x0B\\f\\r \\u00a0]+\\d+[\\t\\n\\x0B\\f\\r \\u00a0]+R|[\\t\\n\\x0B\\f\\r \\u00a0]*<<)")
            .matcher(s);
        return m.find();
    }

    /** Extract (profile own — the CA's production mode). */
    static Extracted extract(byte[] doc, PadesSupport support) throws Failure {
        return extract(doc, "own", support);
    }

    static Extracted extract(byte[] doc, String profile, PadesSupport support) throws Failure {
        if (!support.structureOk(doc)) throw new Failure("structure");
        DReader rdr;
        try {
            rdr = new DReader(doc);
        } catch (RuntimeException e) {
            throw new Failure(encryptRef(doc) ? "encrypted" : "not_pdf");
        }
        if (rdr.trailerValue().keys().contains("Encrypt")) throw new Failure("encrypted");
        List<RawSignature> sigs = new ArrayList<>();
        Map<Integer, Boolean> visible = new HashMap<>();
        String docId = "";
        RawDss dss;
        try {
            for (int xi = 0; xi < rdr.xref.size(); xi++) {
                DReader.Xref x = rdr.xrefAt(xi);
                DReader.Value obj = rdr.resolve(x.ptr, new DReader.PRef(x.ptr[0], x.ptr[1]));
                if (!obj.kind().equals("dict")) continue;
                if (obj.key("FT").name().equals("Sig") && obj.key("V").kind().equals("dict")) {
                    int vp = obj.key("V").ptr[0];
                    if (vp != x.ptr[0]) visible.put(vp, visible.getOrDefault(vp, false) || widgetVisible(obj));
                }
                if (docId.isEmpty() && obj.key("Subtype").name().equals("Link")) {
                    String u = latin1(obj.key("A").key("URI").rawString());
                    if (u.startsWith(AP_VERIFY_PREFIX) && UUID_RE.matcher(u.substring(AP_VERIFY_PREFIX.length())).matches()) {
                        docId = u.substring(AP_VERIFY_PREFIX.length());
                    }
                }
                if (obj.key("Contents").isNull() || obj.key("ByteRange").isNull()) continue;
                String t = obj.key("Type").name();
                if (!t.isEmpty() && !t.equals("Sig")) continue;
                if (sigs.size() == MAX_SIGNATURES) throw new Failure("too_many");
                RawSignature s = extractSignature(doc, obj);
                s.objNum = x.ptr[0];
                sigs.add(s);
            }
            if (sigs.isEmpty()) throw new Failure("no_signature");
            for (RawSignature s : sigs) s.visible = visible.getOrDefault(s.objNum, false);
            dss = extractDss(rdr.trailerValue().key("Root").key("DSS"));
        } catch (Failure e) {
            throw e;
        } catch (RuntimeException | StackOverflowError e) {
            throw new Failure("not_pdf"); // Go: panic → recover → ErrNotPDF
        }
        if (dss != null) for (RawSignature s : sigs) s.dss = dss;
        Map<Integer, long[]> known = new LinkedHashMap<>();
        Map<Integer, SigMeta> metas = new LinkedHashMap<>();
        // Only signatures that pass integrity count as signature-only extensions (Go extract.go): a revision whose
        // "signature" does not verify is classified DSS-only and rejected. name — matched against the stamp's /Name.
        for (RawSignature s : sigs) {
            if (!s.malformed && s.integrity) {
                known.put(s.objNum, s.byteRange);
                metas.put(s.objNum, new SigMeta(1, "", s.claimedRoles.size() <= 1, sealCertificateDer(s.leaf), certDisplayName(s.leaf)));
            }
        }
        for (Map.Entry<Integer, SigMeta> e : metas.entrySet()) {
            long[] br = known.get(e.getKey());
            SigMeta m = e.getValue();
            for (RawSignature s : sigs) {
                if (!s.malformed && s.signedEnd < br[2] + br[3]) m.revIndex++;
                if (s.objNum == e.getKey() && s.claimedRoles.size() == 1) m.role = s.claimedRoles.get(0);
            }
        }
        Revisions revs = null;
        for (RawSignature s : sigs) {
            if (s.malformed || s.coversWhole) continue;
            if (revs == null) {
                revs = new Revisions(doc, known, profile, support);
                revs.sigs = metas;
                revs.docID = docId;
            }
            LaterChanges later = revs.later(s.signedEnd);
            s.laterSignaturesOnly = later.signaturesOnly;
            s.laterSignatures = later.signatures;
            s.laterVisible = later.visible;
        }
        return new Extracted(sigs, metas, docId);
    }

    /** TS sealCertificateDER: an e-Seal certificate (not CA, nonRepudiation without digitalSignature, no EKU). */
    /** Go certDisplayName: the DER certificate's display name (GIVENNAME SURNAME, else CN); "" when it does not parse. */
    static String certDisplayName(byte[] der) {
        if (der == null) return "";
        try {
            return Evaluate.displayName(VCrypto.cert(der));
        } catch (RuntimeException e) {
            return "";
        }
    }

    static boolean sealCertificateDer(byte[] der) {
        if (der == null) return false;
        try {
            Cert c = VCrypto.cert(der);
            int ku = keyUsage(c);
            return !c.isCa() && (ku & 2) != 0 && (ku & 1) == 0 && c.extKeyUsage().isEmpty();
        } catch (RuntimeException e) {
            return false;
        }
    }

    /** Go x509.KeyUsage bit set (bit 0 = digitalSignature … 8 = decipherOnly). */
    static int keyUsage(Cert c) {
        boolean[] ku = c.x509.getKeyUsage();
        if (ku == null) return 0;
        int v = 0;
        for (int i = 0; i < ku.length && i < 9; i++) if (ku[i]) v |= 1 << i;
        return v;
    }

    /** Widget visible: has /AP, or a /Rect with non-zero width and height. */
    private static boolean widgetVisible(DReader.Value w) {
        if (!w.key("AP").isNull()) return true;
        DReader.Value r = w.key("Rect");
        if (!r.kind().equals("array") || r.len() != 4) return false;
        return r.index(0).float64() != r.index(2).float64() && r.index(1).float64() != r.index(3).float64();
    }

    private static String valueText(DReader.Value v) {
        return v.kind().equals("string") ? GoFmt.pdfText(v.rawString()) : "";
    }

    private static RawSignature extractSignature(byte[] doc, DReader.Value obj) {
        RawSignature s = new RawSignature();
        s.signerName = valueText(obj.key("Name"));
        s.reason = valueText(obj.key("Reason"));
        s.location = valueText(obj.key("Location"));
        DReader.Value m = obj.key("M");
        if (!m.isNull()) s.claimedTime = parsePdfDate(valueText(m));
        byte[] contents = obj.key("Contents").rawString();
        long[] br = byteRange(obj.key("ByteRange"));
        Signed sb = signedBytes(doc, br, contents);
        if (sb == null) {
            s.malformed = true;
            return s;
        }
        s.coversWhole = sb.whole;
        s.signedEnd = br[2] + br[3];
        s.byteRange = br;
        s.subFilter = obj.key("SubFilter").name();

        Pkcs7 p7 = parsePkcs7(contents);
        if (p7 == null || p7.signers.size() != 1 || !boundedCerts(p7.certs)) {
            s.malformed = true;
            return s;
        }
        SignerInfo si = p7.signers.get(0);
        Cert leaf = onlySigner(p7);
        if (leaf == null) {
            s.malformed = true;
            return s;
        }
        s.leaf = leaf.raw;
        byte[] der = cmsDer(contents);
        if (der != null) s.cmsSha256 = Text.hex(VCrypto.digest("SHA-256", der));
        signedAttrChecks(si.authAttrs, leaf, s);
        s.claimedRoles = claimedRoles(si.authAttrs);
        for (Attr a : si.authAttrs) {
            if (a.type.equals(O_MESSAGE_DIGEST)) {
                byte[] md = firstOctet(a.values);
                if (md != null) s.messageDigest = Text.hex(md);
            }
        }
        for (Cert c : p7.certs) if (!Arrays.equals(c.raw, leaf.raw)) s.certs.add(c.raw);
        s.weakDigest = !STRONG.contains(si.digestAlg) || SHA1_SIG_ALGS.contains(si.encAlg);
        s.integrity = verifyPkcs7(p7, sb.signed);
        s.timestamp = extractTimestamp(si);
        return s;
    }

    // ── PKCS#7 (the digitorus/pkcs7 subset) ──

    static final String O_SIGNED_DATA = "1.2.840.113549.1.7.2";
    static final String O_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    static final String O_SIGNING_TIME = "1.2.840.113549.1.9.5";
    static final String O_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
    static final String O_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
    static final String O_SIGNER_ATTR_V2 = "0.4.0.19122.1.1";
    static final String O_ROLE = "2.5.4.72";
    private static final Set<String> STRONG = Set.of(VCrypto.SHA256, VCrypto.SHA384, VCrypto.SHA512);
    /**
     * Go weakSignatureOIDs: MD2/MD5/SHA-1 signature algorithms named on a SignerInfo (md2/md5/sha1WithRSAEncryption,
     * dsa-with-sha1, ecdsa-with-SHA1, OIW sha1WithRSASignature) — weak, whatever the digest.
     */
    private static final Set<String> SHA1_SIG_ALGS = Set.of("1.2.840.113549.1.1.2", "1.2.840.113549.1.1.4", "1.2.840.113549.1.1.5",
        "1.2.840.10040.4.3", "1.2.840.10045.4.1", "1.3.14.3.2.29");

    /**
     * Go boundedCerts / boundedCert: ≤ {@link #MAX_CMS_CERTS} certificates, each with a serial ≤ 160 bits (magnitude) and,
     * for RSA, a modulus ≤ 8192 bits and a public exponent ≤ 2^32 − 1. Otherwise the signature is malformed (a timestamp
     * token: not usable).
     */
    static boolean boundedCerts(List<Cert> cs) {
        if (cs.size() > MAX_CMS_CERTS) return false;
        for (Cert c : cs) {
            if (c.serial.abs().bitLength() > VCrypto.MAX_SERIAL_BITS) return false;
            java.security.PublicKey k = c.publicKey();
            if (k instanceof java.security.interfaces.RSAPublicKey) {
                java.security.interfaces.RSAPublicKey r = (java.security.interfaces.RSAPublicKey) k;
                if (r.getModulus().bitLength() > VCrypto.MAX_RSA_BITS || r.getPublicExponent().bitLength() > 32) return false;
            } else if (rsaSpki(c)) {
                return false; // an RSA key the JDK will not load (e.g. modulus > 16384 bits) — outside the bounds anyway
            }
        }
        return true;
    }

    private static boolean rsaSpki(Cert c) {
        try {
            List<Asn1.Node> spki = Asn1.children(Asn1.readNode(c.rawSubjectPublicKeyInfo, 0));
            return Asn1.oid(Asn1.children(spki.get(0)).get(0)).equals("1.2.840.113549.1.1.1");
        } catch (RuntimeException e) {
            return true;
        }
    }

    static final class Attr {
        final String type;
        /** The SET contents (Go Attribute.Value.Bytes). */
        final byte[] values;

        Attr(String type, byte[] values) {
            this.type = type;
            this.values = values;
        }
    }

    static final class SignerInfo {
        byte[] issuer;
        BigInteger serial;
        String digestAlg;
        List<Attr> authAttrs = new ArrayList<>();
        byte[] authRaw;
        String encAlg;
        byte[] sig;
        List<Attr> unauthAttrs = new ArrayList<>();
    }

    static final class Pkcs7 {
        byte[] content = new byte[0];
        final List<Cert> certs = new ArrayList<>();
        final List<SignerInfo> signers = new ArrayList<>();
    }

    /** digitorus pkcs7.Parse: the first TLV (DER) — ContentInfo{SignedData}; every certificate must parse. */
    static Pkcs7 parsePkcs7(byte[] data) {
        try {
            if (data.length == 0) return null;
            List<Asn1.Node> ci = Asn1.children(Asn1.expect(Asn1.readNode(data, 0), Asn1.SEQUENCE, "ContentInfo"));
            if (!Asn1.oid(Asn1.expect(Asn1.at(ci, 0), Asn1.OID, "contentType")).equals(O_SIGNED_DATA)) return null;
            List<Asn1.Node> sd = Asn1.children(Asn1.expect(Asn1.at(Asn1.children(Asn1.expect(Asn1.at(ci, 1), 0xa0, "[0]")), 0), Asn1.SEQUENCE, "SignedData"));
            int i = 0;
            Asn1.expect(Asn1.at(sd, i++), Asn1.INTEGER, "version");
            Asn1.expect(Asn1.at(sd, i++), Asn1.SET, "digestAlgorithms");
            List<Asn1.Node> eci = Asn1.children(Asn1.expect(Asn1.at(sd, i++), Asn1.SEQUENCE, "EncapsulatedContentInfo"));
            Pkcs7 p = new Pkcs7();
            if (Asn1.at(eci, 1) != null) {
                Asn1.Node inner = Asn1.at(Asn1.children(Asn1.expect(eci.get(1), 0xa0, "eContent")), 0);
                if (inner != null && inner.tag == Asn1.OCTET_STRING) {
                    p.content = inner.value();
                } else if (inner != null && inner.tag == 0x24) {
                    java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
                    for (Asn1.Node x : Asn1.children(inner)) o.write(x.buf, x.vs, x.length());
                    p.content = o.toByteArray();
                }
            }
            if (Asn1.at(sd, i) != null && sd.get(i).tag == 0xa0) {
                // Every certificate must parse; the count / serial / RSA bounds are checked by the caller (boundedCerts),
                // after a timestamp token's TSTInfo is read, as Go does.
                for (Asn1.Node c : Asn1.children(sd.get(i))) p.certs.add(VCrypto.certAnySerial(c.raw()));
                i++;
            }
            if (Asn1.at(sd, i) != null && sd.get(i).tag == 0xa1) i++;
            for (Asn1.Node n : Asn1.children(Asn1.expect(Asn1.at(sd, i), Asn1.SET, "signerInfos"))) p.signers.add(parseSignerInfo(n));
            return p;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static List<Attr> parseAttrs(Asn1.Node n) {
        List<Attr> out = new ArrayList<>();
        for (Asn1.Node a : Asn1.children(n)) {
            List<Asn1.Node> tv = Asn1.children(Asn1.expect(a, Asn1.SEQUENCE, "Attribute"));
            out.add(new Attr(Asn1.oid(Asn1.expect(Asn1.at(tv, 0), Asn1.OID, "attr type")), Asn1.expect(Asn1.at(tv, 1), Asn1.SET, "attr values").value()));
        }
        return out;
    }

    private static SignerInfo parseSignerInfo(Asn1.Node n) {
        List<Asn1.Node> f = Asn1.children(Asn1.expect(n, Asn1.SEQUENCE, "SignerInfo"));
        int i = 0;
        SignerInfo si = new SignerInfo();
        Asn1.expect(Asn1.at(f, i++), Asn1.INTEGER, "version");
        List<Asn1.Node> ias = Asn1.children(Asn1.expect(Asn1.at(f, i++), Asn1.SEQUENCE, "IssuerAndSerialNumber"));
        si.issuer = Asn1.expect(Asn1.at(ias, 0), Asn1.SEQUENCE, "issuer").raw();
        si.serial = Asn1.intValue(Asn1.expect(Asn1.at(ias, 1), Asn1.INTEGER, "serial").value());
        si.digestAlg = Asn1.oid(Asn1.expect(Asn1.at(Asn1.children(Asn1.expect(Asn1.at(f, i++), Asn1.SEQUENCE, "digestAlg")), 0), Asn1.OID, "alg"));
        if (Asn1.at(f, i) != null && f.get(i).tag == 0xa0) {
            si.authAttrs = parseAttrs(f.get(i));
            byte[] raw = f.get(i).raw();
            raw[0] = 0x31;
            si.authRaw = raw;
            i++;
        }
        si.encAlg = Asn1.oid(Asn1.expect(Asn1.at(Asn1.children(Asn1.expect(Asn1.at(f, i++), Asn1.SEQUENCE, "encAlg")), 0), Asn1.OID, "alg"));
        si.sig = Asn1.expect(Asn1.at(f, i++), Asn1.OCTET_STRING, "signature").value();
        if (Asn1.at(f, i) != null && f.get(i).tag == 0xa1) si.unauthAttrs = parseAttrs(f.get(i++));
        return si;
    }

    /** GetOnlySigner: the single signer's certificate (RawIssuer + serial). */
    private static Cert onlySigner(Pkcs7 p7) {
        if (p7.signers.size() != 1) return null;
        SignerInfo si = p7.signers.get(0);
        for (Cert c : p7.certs) if (Arrays.equals(c.rawIssuer, si.issuer) && c.serial.equals(si.serial)) return c;
        return null;
    }

    private static final Map<String, String> HASH_FOR_OID = new HashMap<>();
    private static final Set<String> RSA_ENC = Set.of(VCrypto.RSA_ENCRYPTION, "1.2.840.113549.1.1.5", VCrypto.SHA256_RSA, VCrypto.SHA384_RSA,
        VCrypto.SHA512_RSA);
    private static final Set<String> ECDSA_CURVE_ENC = Set.of(VCrypto.P256, VCrypto.P384, VCrypto.P521);

    static {
        HASH_FOR_OID.put(VCrypto.SHA1, "SHA-1");
        HASH_FOR_OID.put("1.2.840.10045.4.1", "SHA-1");
        HASH_FOR_OID.put("1.2.840.10040.4.1", "SHA-1");
        HASH_FOR_OID.put("1.2.840.10040.4.3", "SHA-1");
        HASH_FOR_OID.put(VCrypto.RSA_ENCRYPTION, "SHA-1");
        HASH_FOR_OID.put(VCrypto.SHA256, "SHA-256");
        HASH_FOR_OID.put(VCrypto.ECDSA_SHA256, "SHA-256");
        HASH_FOR_OID.put(VCrypto.SHA384, "SHA-384");
        HASH_FOR_OID.put(VCrypto.ECDSA_SHA384, "SHA-384");
        HASH_FOR_OID.put(VCrypto.SHA512, "SHA-512");
        HASH_FOR_OID.put(VCrypto.ECDSA_SHA512, "SHA-512");
    }

    /** digitorus getSignatureAlgorithm → the x509 signature algorithm OID (null = unsupported; RSASSA-PSS is not, like the references). */
    private static String sigAlgOid(String encAlg, String digestAlg) {
        switch (encAlg) {
            case "1.2.840.10045.4.1":
            case VCrypto.ECDSA_SHA256:
            case VCrypto.ECDSA_SHA384:
            case VCrypto.ECDSA_SHA512:
                return encAlg;
            default:
                break;
        }
        if (RSA_ENC.contains(encAlg)) {
            switch (digestAlg) {
                case VCrypto.SHA1: return "1.2.840.113549.1.1.5";
                case VCrypto.SHA256: return VCrypto.SHA256_RSA;
                case VCrypto.SHA384: return VCrypto.SHA384_RSA;
                case VCrypto.SHA512: return VCrypto.SHA512_RSA;
                default: return null;
            }
        }
        if (ECDSA_CURVE_ENC.contains(encAlg)) {
            switch (digestAlg) {
                case VCrypto.SHA1: return "1.2.840.10045.4.1";
                case VCrypto.SHA256: return VCrypto.ECDSA_SHA256;
                case VCrypto.SHA384: return VCrypto.ECDSA_SHA384;
                case VCrypto.SHA512: return VCrypto.ECDSA_SHA512;
                default: return null;
            }
        }
        return null;
    }

    /** digitorus pkcs7.Verify (truststore nil): messageDigest, signingTime within the certificate validity, signature. */
    static boolean verifyPkcs7(Pkcs7 p7, byte[] content) {
        if (p7.signers.isEmpty()) return false;
        for (SignerInfo si : p7.signers) {
            Cert ee = null;
            for (Cert c : p7.certs) {
                if (Arrays.equals(c.rawIssuer, si.issuer) && c.serial.equals(si.serial)) {
                    ee = c;
                    break;
                }
            }
            if (ee == null) return false;
            byte[] signed = content;
            if (!si.authAttrs.isEmpty()) {
                byte[] md = null;
                for (Attr a : si.authAttrs) {
                    if (a.type.equals(O_MESSAGE_DIGEST)) {
                        md = firstOctet(a.values);
                        break;
                    }
                }
                if (md == null) return false;
                String hash = HASH_FOR_OID.get(si.digestAlg);
                if (hash == null) return false;
                if (!Arrays.equals(md, VCrypto.digest(hash, content))) return false;
                signed = si.authRaw;
                for (Attr a : si.authAttrs) {
                    if (!a.type.equals(O_SIGNING_TIME)) continue;
                    Instant t = attrTime(a.values);
                    if (t != null && (t.toEpochMilli() > ee.x509.getNotAfter().getTime() || t.toEpochMilli() < ee.x509.getNotBefore().getTime())) {
                        return false;
                    }
                    break;
                }
            }
            String alg = sigAlgOid(si.encAlg, si.digestAlg);
            if (alg == null) return false;
            boolean ok;
            try {
                ok = VCrypto.verify(ee, VCrypto.algNode(alg), signed, si.sig);
            } catch (RuntimeException e) {
                ok = false;
            }
            if (!ok) return false;
        }
        return true;
    }

    private static byte[] firstOctet(byte[] values) {
        try {
            Asn1.Node n = Asn1.readNode(values, 0);
            return n.tag == Asn1.OCTET_STRING ? n.value() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Instant attrTime(byte[] values) {
        try {
            Asn1.Node n = Asn1.readNode(values, 0);
            if (n.tag != Asn1.UTC_TIME && n.tag != Asn1.GENERALIZED_TIME) return null;
            Instant t = Asn1.preciseTime(n);
            return Instant.ofEpochMilli(t.toEpochMilli()); // TS compares the Date (ms)
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** The first ASN.1 element of /Contents (the CMS without the placeholder's zero padding). */
    private static byte[] cmsDer(byte[] contents) {
        try {
            Asn1.Node n = Asn1.readNode(contents, 0);
            return n.tag == Asn1.SEQUENCE ? n.raw() : null;
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ── signedAttrs ──

    /** Go signedAttrChecks: signingCertificateV2 matches the leaf; signingTime present. */
    private static void signedAttrChecks(List<Attr> attrs, Cert leaf, RawSignature s) {
        String certV2 = "";
        boolean signingTime = false;
        for (Attr a : attrs) {
            if (a.type.equals(O_SIGNING_TIME)) {
                signingTime = true;
                continue;
            }
            if (!a.type.equals(O_SIGNING_CERT_V2)) continue;
            if (!certV2.isEmpty()) {
                certV2 = "mismatch";
                continue;
            }
            certV2 = "mismatch";
            try {
                Asn1.Node top = Asn1.readNode(a.values, 0);
                if (top.rawLength() != a.values.length || top.tag != Asn1.SEQUENCE) continue;
                List<Asn1.Node> scf = Asn1.children(top);
                if (scf.size() != 1 || scf.get(0).tag != Asn1.SEQUENCE) continue;
                List<Asn1.Node> ids = Asn1.children(scf.get(0));
                if (ids.isEmpty()) continue;
                List<Asn1.Node> id = Asn1.children(Asn1.expect(ids.get(0), Asn1.SEQUENCE, "ESSCertIDv2"));
                int k = 0;
                String hash = "SHA-256";
                if (Asn1.at(id, k) != null && id.get(k).tag == Asn1.SEQUENCE) {
                    String alg = Asn1.oid(Asn1.expect(Asn1.at(Asn1.children(id.get(k)), 0), Asn1.OID, "alg"));
                    hash = alg.equals(VCrypto.SHA256) ? "SHA-256" : alg.equals(VCrypto.SHA384) ? "SHA-384" : alg.equals(VCrypto.SHA512) ? "SHA-512" : null;
                    k++;
                }
                byte[] certHash = Asn1.expect(Asn1.at(id, k++), Asn1.OCTET_STRING, "certHash").value();
                BigInteger serial = null;
                if (Asn1.at(id, k) != null) {
                    List<Asn1.Node> is = Asn1.children(Asn1.expect(id.get(k), Asn1.SEQUENCE, "IssuerSerial"));
                    serial = Asn1.intValue(Asn1.expect(Asn1.at(is, 1), Asn1.INTEGER, "serial").value());
                    k++;
                }
                if (k != id.size() || hash == null) continue;
                if (!Arrays.equals(VCrypto.digest(hash, leaf.raw), certHash)) continue;
                if (serial != null && !serial.equals(leaf.serial)) continue;
                certV2 = "match";
            } catch (RuntimeException e) {
                // mismatch
            }
        }
        s.signingCertV2 = certV2;
        s.signingTimeAttr = signingTime;
    }

    /** signer-attributes-v2 claimedAttributes / id-at-role (UTF8String / PrintableString). */
    private static List<String> claimedRoles(List<Attr> attrs) {
        List<String> out = new ArrayList<>();
        for (Attr a : attrs) {
            if (!a.type.equals(O_SIGNER_ATTR_V2)) continue;
            try {
                Asn1.Node seq = Asn1.readNode(a.values, 0);
                if (seq.tag != Asn1.SEQUENCE) continue;
                Asn1.Node first = seq.length() > 0 ? Asn1.readNode(seq.buf, seq.vs, seq.end) : null;
                if (first == null || first.tag != 0xa0) continue;
                Asn1.Node list = Asn1.readNode(first.buf, first.vs, first.end);
                if (list.tag != Asn1.SEQUENCE) continue;
                int p = list.vs;
                while (p < list.end && out.size() < MAX_CLAIMED_ROLES) {
                    Asn1.Node at;
                    try {
                        at = Asn1.readNode(list.buf, p, list.end);
                    } catch (RuntimeException e) {
                        break;
                    }
                    p = at.end;
                    if (at.tag != Asn1.SEQUENCE) break;
                    List<Asn1.Node> parts = Asn1.children(at);
                    if (Asn1.at(parts, 0) == null || parts.get(0).tag != Asn1.OID || Asn1.at(parts, 1) == null || parts.get(1).tag != Asn1.SET) break;
                    if (!Asn1.oid(parts.get(0)).equals(O_ROLE)) continue;
                    Asn1.Node vals = parts.get(1);
                    int q = vals.vs;
                    while (q < vals.end && out.size() < MAX_CLAIMED_ROLES) {
                        Asn1.Node v;
                        try {
                            v = Asn1.readNode(vals.buf, q, vals.end);
                        } catch (RuntimeException e) {
                            break;
                        }
                        q = v.end;
                        if (v.tag != Asn1.UTF8 && v.tag != Asn1.PRINTABLE) continue;
                        String r = validClaimedRole(v.value());
                        if (r != null) out.add(r);
                    }
                }
            } catch (RuntimeException e) {
                // skipped
            }
        }
        return out;
    }

    /** Go validClaimedRole: non-empty, valid UTF-8, ≤ 900 runes, no control (Cc) or format (Cf) characters. */
    private static String validClaimedRole(byte[] b) {
        String s;
        try {
            s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(java.nio.ByteBuffer.wrap(b)).toString();
        } catch (CharacterCodingException e) {
            return null;
        }
        if (s.isEmpty() || s.codePointCount(0, s.length()) > MAX_CLAIMED_ROLE_RUNES) return null;
        for (int i = 0; i < s.length(); ) {
            int c = s.codePointAt(i);
            int t = Character.getType(c);
            if (t == Character.CONTROL || t == Character.FORMAT) return null;
            i += Character.charCount(c);
        }
        return s;
    }

    // ── RFC 3161 ──

    private static RawTimestamp extractTimestamp(SignerInfo si) {
        for (Attr a : si.unauthAttrs) {
            if (!a.type.equals(O_TIMESTAMP_TOKEN)) continue;
            RawTimestamp out = new RawTimestamp();
            Pkcs7 tok = parsePkcs7(a.values);
            if (tok == null) return out;
            if (!tok.certs.isEmpty() && !verifyPkcs7(tok, tok.content)) return out;
            String hashAlg;
            byte[] hashed;
            Instant time;
            String serial;
            try {
                List<Asn1.Node> info = Asn1.children(Asn1.expect(Asn1.parseOne(tok.content), Asn1.SEQUENCE, "TSTInfo"));
                List<Asn1.Node> mi = Asn1.children(Asn1.expect(Asn1.at(info, 2), Asn1.SEQUENCE, "messageImprint"));
                hashAlg = Asn1.oid(Asn1.expect(Asn1.at(Asn1.children(Asn1.expect(Asn1.at(mi, 0), Asn1.SEQUENCE, "alg")), 0), Asn1.OID, "alg"));
                hashed = Asn1.expect(Asn1.at(mi, 1), Asn1.OCTET_STRING, "hashedMessage").value();
                if (hashed.length == 0) return out;
                Asn1.Node sn = Asn1.expect(Asn1.at(info, 3), Asn1.INTEGER, "serial");
                // TSTInfo serialNumber ≤ 160 bits of magnitude (Go: ts.SerialNumber.BitLen() > maxSerialBits → unusable)
                if (sn.length() > 64 || Asn1.intValue(sn.value()).abs().bitLength() > VCrypto.MAX_SERIAL_BITS) return out;
                serial = GoFmt.hexSerial(sn.value());
                time = Asn1.preciseTime(Asn1.expect(Asn1.at(info, 4), Asn1.GENERALIZED_TIME, "genTime"));
            } catch (RuntimeException e) {
                return out;
            }
            out.time = time;
            out.serial = serial;
            if (tok.signers.size() != 1 || !boundedCerts(tok.certs)) return out;
            Cert tsa = onlySigner(tok);
            if (tsa == null) return out;
            out.tsaCert = tsa.raw;
            for (Cert c : tok.certs) if (!Arrays.equals(c.raw, tsa.raw)) out.certs.add(c.raw);
            String h = VCrypto.hashName(hashAlg);
            out.weakDigest = !STRONG.contains(tok.signers.get(0).digestAlg) || SHA1_SIG_ALGS.contains(tok.signers.get(0).encAlg) || !(h != null && !h.equals("SHA-1"));
            if (h == null) return out;
            out.matches = Arrays.equals(VCrypto.digest(h, si.sig), hashed);
            return out;
        }
        return null;
    }

    // ── ByteRange / dates / DSS ──

    private static final class Signed {
        final byte[] signed;
        final boolean whole;

        Signed(byte[] signed, boolean whole) {
            this.signed = signed;
            this.whole = whole;
        }
    }

    /** ByteRange [0 a b c]: the gap is EXACTLY this dictionary's /Contents <hex>. */
    private static Signed signedBytes(byte[] doc, long[] br, byte[] contents) {
        if (br == null || br.length != 4) return null;
        long n = doc.length;
        long a0 = br[0];
        long l0 = br[1];
        long a1 = br[2];
        long l1 = br[3];
        if (a0 != 0 || l0 <= 0 || l1 < 0 || a1 <= l0 || a1 > n || l1 > n - a1) return null;
        int gs = (int) l0;
        int ge = (int) a1;
        if (ge - gs < 2 || doc[gs] != '<' || doc[ge - 1] != '>') return null;
        int hexLen = ge - gs - 2;
        if (hexLen % 2 != 0) return null;
        for (int i = gs + 1; i < ge - 1; i++) if (Text.hexVal(doc[i] & 0xff) < 0) return null;
        if (hexLen / 2 != contents.length) return null;
        for (int i = 0; i < contents.length; i++) {
            int v = (Text.hexVal(doc[gs + 1 + 2 * i] & 0xff) << 4) | Text.hexVal(doc[gs + 2 + 2 * i] & 0xff);
            if ((byte) v != contents[i]) return null;
        }
        byte[] signed = new byte[(int) (l0 + l1)];
        System.arraycopy(doc, 0, signed, 0, (int) l0);
        System.arraycopy(doc, (int) a1, signed, (int) l0, (int) l1);
        return new Signed(signed, a1 + l1 == n);
    }

    private static long[] byteRange(DReader.Value v) {
        if (!v.kind().equals("array") || v.len() != 4) return null;
        long[] out = new long[4];
        for (int i = 0; i < 4; i++) {
            DReader.Value e = v.index(i);
            if (!e.kind().equals("int")) return null;
            out[i] = e.int64();
        }
        return out;
    }

    private static final Pattern PDF_DATE = Pattern.compile("^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(Z|[+-]\\d{4})?$");

    /** Go parsePDFDate: strip "D:", drop "'", then 20060102150405[-0700|Z0700|Z|]. */
    static Instant parsePdfDate(String raw) {
        String s = (raw.startsWith("D:") ? raw.substring(2) : raw).replace("'", "");
        Matcher m = PDF_DATE.matcher(s);
        if (!m.matches()) return null;
        int y = Integer.parseInt(m.group(1));
        int mo = Integer.parseInt(m.group(2));
        int d = Integer.parseInt(m.group(3));
        int h = Integer.parseInt(m.group(4));
        int mi = Integer.parseInt(m.group(5));
        int se = Integer.parseInt(m.group(6));
        if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) return null;
        boolean leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        int[] dim = {31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
        if (d > dim[mo - 1]) return null;
        long off = 0;
        String z = m.group(7);
        if (z != null && !z.equals("Z")) {
            int oh = Integer.parseInt(z.substring(1, 3));
            int om = Integer.parseInt(z.substring(3, 5));
            if (oh > 24 || om > 59) return null;
            off = (oh * 60L + om) * 60L * (z.charAt(0) == '+' ? 1 : -1);
        }
        long t = LocalDateTime.of(y, mo, d, h, mi, se).toEpochSecond(ZoneOffset.UTC);
        return Instant.ofEpochSecond(t - off);
    }

    /** /DSS /Certs /OCSPs /CRLs streams, decoded; unparsable / over-limit entries skipped. */
    private static RawDss extractDss(DReader.Value dss) {
        if (!dss.kind().equals("dict")) return null;
        long[] total = {0};
        return new RawDss(readDss(dss, "Certs", total), readDss(dss, "OCSPs", total), readDss(dss, "CRLs", total));
    }

    /**
     * One DSS array. Items over 1 MiB are skipped (the raw /Length and the decoded size are checked before anything is
     * kept); the same stream object is read once per array (Go extractDss); all DSS items together are capped at
     * {@link #MAX_DSS_TOTAL} bytes, in /Certs → /OCSPs → /CRLs order.
     */
    private static List<byte[]> readDss(DReader.Value dss, String key, long[] total) {
        DReader.Value arr = dss.key(key);
        java.util.Set<Object> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        List<byte[]> out = new ArrayList<>();
        for (int i = 0; i < arr.len() && i < MAX_DSS_ITEMS; i++) {
            DReader.Value e = arr.index(i);
            if (!e.kind().equals("stream")) continue;
            if (!seen.add(e.data)) continue;
            byte[] b;
            try {
                long n = e.streamLength();
                if (n < 0 || n > MAX_DSS_STREAM) continue;
                b = e.streamData(MAX_DSS_STREAM);
            } catch (RuntimeException x) {
                continue;
            }
            if (b.length > MAX_DSS_STREAM || total[0] + b.length > MAX_DSS_TOTAL) continue;
            total[0] += b.length;
            out.add(b);
        }
        return out;
    }
}
