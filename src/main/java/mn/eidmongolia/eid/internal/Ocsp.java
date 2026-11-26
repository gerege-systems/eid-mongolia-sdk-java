package mn.eidmongolia.eid.internal;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OCSP (RFC 6960) request/response — x/crypto/ocsp semantics the Go reference uses. Shared by the PAdES LTV collection
 * ({@link #parseForCert}, {@link #certIdMatches}, {@link #responderOk}) and the RP revocation checker
 * ({@link #parseResponseForCert}).
 */
public final class Ocsp {
    public static final int GOOD = 0;
    public static final int REVOKED = 1;
    public static final int UNKNOWN = 2;
    private static final String OID_SHA1 = "1.3.14.3.2.26";
    private static final String OID_BASIC = "1.3.6.1.5.5.7.48.1.1";

    private Ocsp() {
    }

    private static void check(boolean ok, String msg) {
        if (!ok) throw new IllegalArgumentException(msg);
    }

    private static byte[] sha1(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-1").digest(b);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1", e);
        }
    }

    public static final class Response {
        public final int status;
        public final Date thisUpdate;
        public final Date nextUpdate;
        public final Cert certificate;

        Response(int status, Date thisUpdate, Date nextUpdate, Cert certificate) {
            this.status = status;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.certificate = certificate;
        }
    }

    /** OCSPRequest { tbsRequest { requestList { Request { CertID(SHA-1 + NULL) } } } } (x/crypto CreateRequest). */
    public static byte[] request(Cert c, Cert issuer) {
        byte[] certId = Der.seq(Der.seq(Der.oid(OID_SHA1), Der.nullValue()), Der.octets(sha1(issuer.rawSubject)),
            Der.octets(sha1(issuer.publicKeyBits)), Der.integer(c.serial));
        return Der.seq(Der.seq(Der.seq(Der.seq(certId))));
    }

    /**
     * PAdES LTV parse (unchanged from the pades package): signature by issuer or by an included cert the issuer signed;
     * the cert's SingleResponse.
     */
    public static Response parseForCert(byte[] der, Cert c, Cert issuer) {
        List<Der.Tlv> top = Der.parse(der).children();
        byte[] st = top.get(0).value();
        check(top.get(0).tag == Der.ENUMERATED && st.length == 1 && st[0] == 0, "OCSP response status");
        Der.Tlv rb = top.get(1).child(0);
        check(rb.child(0).oid().equals(OID_BASIC), "not a basic OCSP response");
        List<Der.Tlv> basic = Der.parse(rb.child(1).value()).children();
        Der.Tlv tbs = basic.get(0);
        String sigOid = basic.get(1).child(0).oid();
        Der.Tlv bits = basic.get(2);
        byte[] sig = Arrays.copyOfRange(bits.buf, bits.valueStart + 1, bits.end);
        Cert responder = null;
        if (basic.size() > 3 && basic.get(3).tag == Der.ctx(0)) {
            List<Der.Tlv> certs = basic.get(3).child(0).children();
            if (!certs.isEmpty()) responder = Cert.parse(certs.get(0).encoded());
            for (int k = 1; k < certs.size(); k++) Cert.parse(certs.get(k).encoded());
        }
        if (responder != null) {
            check(responder.equals(issuer) || responder.signedBy(issuer), "OCSP responder not issued by the issuer");
            check(Sig.verifyOid(sigOid, responder.publicKey(), tbs.encoded(), sig), "OCSP signature");
        } else {
            check(Sig.verifyOid(sigOid, issuer.publicKey(), tbs.encoded(), sig), "OCSP signature");
        }
        List<Der.Tlv> rd = tbs.children();
        int i = rd.get(0).tag == Der.ctx(0) ? 1 : 0;
        i += 2; // responderID, producedAt
        Der.Tlv single = null;
        for (Der.Tlv s : rd.get(i).children()) {
            if (s.child(0).child(3).bigInt().equals(c.serial)) {
                single = s;
                break;
            }
        }
        if (single == null) throw new IllegalArgumentException("no OCSP response for the certificate");
        List<Der.Tlv> s = single.children();
        int tag = s.get(1).tag & 0x1f;
        int status = tag == 0 ? 0 : tag == 1 ? 1 : 2;
        Date thisUpdate = Asn1Time.parse(s.get(2));
        Date next = null;
        for (int k = 3; k < s.size(); k++) {
            if (s.get(k).tag == Der.ctx(0)) {
                next = Asn1Time.parse(s.get(k).child(0));
                break;
            }
        }
        return new Response(status, thisUpdate, next, responder);
    }

    private static final Map<String, String> HASHES = new HashMap<>();

    static {
        HASHES.put("1.3.14.3.2.26", "SHA-1");
        HASHES.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        HASHES.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        HASHES.put("2.16.840.1.101.3.4.2.3", "SHA-512");
    }

    /**
     * Go `validate.OCSPCertIDMatches`: every SingleResponse for [c]'s serial carries [issuer]'s CertID and there is at
     * least one.
     */
    public static boolean certIdMatches(byte[] der, Cert c, Cert issuer) {
        try {
            List<Der.Tlv> top = Der.parse(der).children();
            byte[] st = top.get(0).value();
            if (top.get(0).tag != Der.ENUMERATED || st.length != 1 || st[0] != 0) return false;
            List<Der.Tlv> basic = Der.parse(top.get(1).child(0).child(1).value()).children();
            List<Der.Tlv> rd = basic.get(0).children();
            int i = rd.get(0).tag == Der.ctx(0) ? 1 : 0;
            i += 2; // responderID, producedAt
            boolean found = false;
            for (Der.Tlv single : rd.get(i).children()) {
                List<Der.Tlv> id = single.child(0).children();
                if (id.size() != 4 || id.get(1).tag != Der.OCTET_STRING || id.get(2).tag != Der.OCTET_STRING || id.get(3).tag != Der.INTEGER) {
                    return false;
                }
                if (!id.get(3).bigInt().equals(c.serial)) continue;
                String h = HASHES.get(id.get(0).child(0).oid());
                if (h == null) return false;
                if (!Arrays.equals(id.get(1).value(), MessageDigest.getInstance(h).digest(issuer.rawSubject))
                    || !Arrays.equals(id.get(2).value(), MessageDigest.getInstance(h).digest(issuer.publicKeyBits))) {
                    return false;
                }
                found = true;
            }
            return found;
        } catch (Exception e) {
            return false;
        }
    }

    /** Go responderOK: issuer itself, or a responder certificate with id-kp-OCSPSigning. */
    public static boolean responderOk(Response r, Cert issuer) {
        return r.certificate == null || r.certificate.equals(issuer) || r.certificate.extKeyUsage().contains(Cert.OID_KP_OCSP_SIGNING);
    }

    // ── x/crypto/ocsp ParseResponseForCert (the RP revocation checker, Go ocsp.go) ──

    /** {@link ParseException#kind}: responseStatus not successful (x/crypto ResponseError). */
    public static final String KIND_RESPONDER_STATUS = "responder_status";
    /** Bad response signature, or the embedded responder certificate not signed by the issuer. */
    public static final String KIND_SIGNATURE = "signature";
    /** No SingleResponse for the certificate's serial. */
    public static final String KIND_INVALID = "invalid";
    /** Anything else that does not parse. */
    public static final String KIND_PARSE = "parse";

    /** A response {@link #parseResponseForCert} rejects; {@link #kind} classifies it like Go {@code ocspParseKind}. */
    public static final class ParseException extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        public final String kind;

        ParseException(String kind, String message) {
            super(message);
            this.kind = kind;
        }
    }

    /** A parsed single response (x/crypto {@code ocsp.Response}, the fields the checker uses). */
    public static final class Parsed {
        /** {@link #GOOD}, {@link #REVOKED} or {@link #UNKNOWN}. */
        public final int status;
        public final BigInteger serial;
        public final Date thisUpdate;
        /** null when absent. */
        public final Date nextUpdate;
        /** The first embedded certificate (responder), or null. */
        public final Cert certificate;
        private final byte[] tbs;
        private final String sigOid;
        private final byte[] signature;

        Parsed(int status, BigInteger serial, Date thisUpdate, Date nextUpdate, Cert certificate, byte[] tbs, String sigOid,
               byte[] signature) {
            this.status = status;
            this.serial = serial;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.certificate = certificate;
            this.tbs = tbs;
            this.sigOid = sigOid;
            this.signature = signature;
        }

        /** x/crypto {@code Response.CheckSignatureFrom}: the response signature verifies with [k]'s key. */
        public boolean signedBy(Cert k) {
            return Sig.verifyOid(sigOid, k.publicKey(), tbs, signature);
        }
    }

    private static final class Single {
        BigInteger serial;
        String hashOid;
        int status;
        Date thisUpdate;
        Date nextUpdate;
        boolean criticalExtension;
    }

    private static ParseException parseErr(String msg) {
        return new ParseException(KIND_PARSE, msg);
    }

    private static List<Der.Tlv> kids(Der.Tlv t, int tag, String what) {
        if (t.tag != tag) throw parseErr("OCSP: " + what);
        return t.children();
    }

    private static Date generalized(Der.Tlv t, String what) {
        if (t.tag != Der.GENERALIZED_TIME) throw parseErr("OCSP: " + what);
        return Asn1Time.parse(t);
    }

    /**
     * x/crypto/ocsp {@code ParseResponseForCert(der, cert, issuer)}, check for check: the response parses (no trailing
     * data), responseStatus successful ({@link #KIND_RESPONDER_STATUS}), a basic response with ≥ 1 SingleResponse, the
     * one for [cert]'s serial ({@link #KIND_INVALID} when none), responderID byName / byKey; with an embedded
     * certificate the response is signed by it and — when [issuer] is given — it is signed by [issuer]; without one the
     * response is signed by [issuer] ({@link #KIND_SIGNATURE}); no critical single extension; CertID hash SHA-1/256/384/512.
     * [issuer] null skips the issuer checks (Go ocsp.go's self-embedding retry).
     */
    public static Parsed parseResponseForCert(byte[] der, Cert cert, Cert issuer) {
        // ── structure (Go asn1.Unmarshal of responseASN1 + basicResponse) ──
        int respStatus;
        List<Der.Tlv> basic;
        Der.Tlv tbs;
        String sigOid;
        byte[] sig;
        int responderTag;
        List<Single> singles = new ArrayList<>();
        List<Der.Tlv> certs = new ArrayList<>();
        try {
            Der.Tlv top = Der.parse(der);
            if (top.tag != Der.SEQUENCE || top.end != der.length) throw parseErr("trailing data in OCSP response");
            List<Der.Tlv> f = top.children();
            if (f.isEmpty() || f.get(0).tag != Der.ENUMERATED || f.get(0).length() == 0) throw parseErr("OCSP: responseStatus");
            respStatus = f.get(0).bigInt().intValue();
            if (f.size() > 2 || f.size() == 2 && f.get(1).tag != Der.ctx(0)) throw parseErr("OCSP: responseBytes");
            if (respStatus != 0) throw new ParseException(KIND_RESPONDER_STATUS, "OCSP responseStatus " + respStatus);
            if (f.size() < 2) throw parseErr("bad OCSP response type");
            List<Der.Tlv> rb = kids(f.get(1).child(0), Der.SEQUENCE, "ResponseBytes");
            if (rb.size() != 2 || rb.get(0).tag != Der.OID || !rb.get(0).oid().equals(OID_BASIC)) throw parseErr("bad OCSP response type");
            if (rb.get(1).tag != Der.OCTET_STRING) throw parseErr("OCSP: response");
            byte[] inner = rb.get(1).value();
            Der.Tlv b = Der.parse(inner);
            if (b.end != inner.length) throw parseErr("trailing data in OCSP response");
            basic = kids(b, Der.SEQUENCE, "BasicOCSPResponse");
            if (basic.size() < 3) throw parseErr("OCSP: BasicOCSPResponse");
            tbs = basic.get(0);
            List<Der.Tlv> alg = kids(basic.get(1), Der.SEQUENCE, "signatureAlgorithm");
            if (alg.isEmpty() || alg.get(0).tag != Der.OID) throw parseErr("OCSP: signatureAlgorithm");
            sigOid = alg.get(0).oid();
            Der.Tlv bits = basic.get(2);
            if (bits.tag != Der.BIT_STRING || bits.length() < 1) throw parseErr("OCSP: signature");
            sig = Arrays.copyOfRange(bits.buf, bits.valueStart + 1, bits.end);
            if (basic.size() > 3) {
                if (basic.get(3).tag != Der.ctx(0) || basic.size() > 4) throw parseErr("OCSP: certs");
                certs = kids(basic.get(3).child(0), Der.SEQUENCE, "certs");
            }
            List<Der.Tlv> rd = kids(tbs, Der.SEQUENCE, "tbsResponseData");
            int i = !rd.isEmpty() && rd.get(0).tag == Der.ctx(0) ? 1 : 0;
            if (rd.size() < i + 3) throw parseErr("OCSP: tbsResponseData");
            responderTag = rd.get(i++).tag;
            generalized(rd.get(i++), "producedAt");
            for (Der.Tlv s : kids(rd.get(i), Der.SEQUENCE, "responses")) singles.add(single(s));
        } catch (ParseException e) {
            throw e;
        } catch (RuntimeException e) {
            throw parseErr("OCSP: " + e.getMessage());
        }
        if (singles.isEmpty() || cert == null && singles.size() > 1) throw parseErr("OCSP response contains bad number of responses");
        Single one = null;
        if (cert == null) {
            one = singles.get(0);
        } else {
            for (Single s : singles) {
                if (cert.serial.equals(s.serial)) {
                    one = s;
                    break;
                }
            }
            if (one == null) throw new ParseException(KIND_INVALID, "no response matching the supplied certificate");
        }
        if (responderTag != Der.ctx(1) && responderTag != Der.ctx(2)) {
            throw parseErr("invalid responder id tag");
        }
        Cert embedded = null;
        Parsed out;
        if (!certs.isEmpty()) {
            try {
                embedded = Cert.parse(certs.get(0).encoded());
            } catch (RuntimeException e) {
                throw parseErr("OCSP: embedded certificate: " + e.getMessage());
            }
        }
        out = new Parsed(one.status, one.serial, one.thisUpdate, one.nextUpdate, embedded, tbs.encoded(), sigOid, sig);
        if (embedded != null) {
            if (!out.signedBy(embedded)) throw new ParseException(KIND_SIGNATURE, "bad signature on embedded certificate");
            if (issuer != null && !embedded.signedBy(issuer)) throw new ParseException(KIND_SIGNATURE, "bad OCSP signature");
        } else if (issuer != null && !out.signedBy(issuer)) {
            throw new ParseException(KIND_SIGNATURE, "bad OCSP signature");
        }
        if (one.criticalExtension) throw parseErr("unsupported critical extension");
        if (!HASHES.containsKey(one.hashOid)) throw parseErr("unsupported issuer hash algorithm");
        return out;
    }

    /** SingleResponse { certID, certStatus, thisUpdate, [0] nextUpdate, [1] singleExtensions }. */
    private static Single single(Der.Tlv t) {
        List<Der.Tlv> s = kids(t, Der.SEQUENCE, "SingleResponse");
        if (s.size() < 3) throw parseErr("OCSP: SingleResponse");
        List<Der.Tlv> id = kids(s.get(0), Der.SEQUENCE, "CertID");
        if (id.size() != 4 || id.get(1).tag != Der.OCTET_STRING || id.get(2).tag != Der.OCTET_STRING || id.get(3).tag != Der.INTEGER
            || id.get(3).length() == 0) {
            throw parseErr("OCSP: CertID");
        }
        List<Der.Tlv> h = kids(id.get(0), Der.SEQUENCE, "CertID hashAlgorithm");
        if (h.isEmpty() || h.get(0).tag != Der.OID) throw parseErr("OCSP: CertID hashAlgorithm");
        Single out = new Single();
        out.hashOid = h.get(0).oid();
        out.serial = id.get(3).bigInt();
        int st = s.get(1).tag;
        if (st == Der.ctx(0, false)) {
            out.status = GOOD;
        } else if (st == Der.ctx(1)) {
            out.status = REVOKED;
        } else if (st == Der.ctx(2, false)) {
            out.status = UNKNOWN;
        } else {
            throw parseErr("OCSP: certStatus");
        }
        out.thisUpdate = generalized(s.get(2), "thisUpdate");
        for (int k = 3; k < s.size(); k++) {
            Der.Tlv x = s.get(k);
            if (x.tag == Der.ctx(0)) {
                out.nextUpdate = generalized(x.child(0), "nextUpdate");
            } else if (x.tag == Der.ctx(1)) {
                for (Der.Tlv ext : kids(x.child(0), Der.SEQUENCE, "singleExtensions")) {
                    List<Der.Tlv> e = kids(ext, Der.SEQUENCE, "Extension");
                    if (e.size() == 3 && e.get(1).tag == Der.BOOLEAN && e.get(1).length() == 1 && e.get(1).buf[e.get(1).valueStart] != 0) {
                        out.criticalExtension = true;
                    }
                }
            } else {
                throw parseErr("OCSP: SingleResponse");
            }
        }
        return out;
    }

    /** Go ocsp.go {@code sameCertKey}: byte-identical, or the same subject and public key (a re-issued CA). */
    public static boolean sameCertKey(Cert a, Cert b) {
        return Arrays.equals(a.raw, b.raw)
            || Arrays.equals(a.rawSubject, b.rawSubject) && Arrays.equals(a.rawSubjectPublicKeyInfo, b.rawSubjectPublicKeyInfo);
    }
}
