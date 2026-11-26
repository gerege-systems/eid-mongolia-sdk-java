package mn.eidmongolia.eid.pades.validate;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;

/**
 * OCSP / CRL evidence rules — TS src/pades/revocation.ts (Go pades/internal/validate/revocation.go) and the OCSP part of
 * TS src/pades/ltv.ts (x/crypto/ocsp ParseResponseForCert). Times keep nanoseconds (Go time.Time).
 */
final class Revocation {
    static final Duration MAX_AGE = Duration.ofHours(24);
    static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    private static final String OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
    private static final String OID_AKI = "2.5.29.35";
    /** SHA-1 / MD5 signature algorithms (Go CheckSignature rejects them). */
    static final Set<String> SHA1_SIG = Set.of("1.2.840.113549.1.1.5", "1.2.840.10045.4.1", "1.2.840.10040.4.3", "1.2.840.113549.1.1.4");

    private Revocation() {
    }

    static boolean before(Instant a, Instant b) {
        return a.compareTo(b) < 0;
    }

    static boolean after(Instant a, Instant b) {
        return a.compareTo(b) > 0;
    }

    /** Go validate.FreshAt (see TS freshAt). nextUpdate ZERO = absent. */
    static boolean freshAt(Instant thisUpdate, Instant nextUpdate, Instant at, Instant now) {
        if (GoFmt.isZero(thisUpdate) || after(thisUpdate, now.plus(CLOCK_SKEW))) return false;
        if (!GoFmt.isZero(nextUpdate) && before(nextUpdate, at.minus(CLOCK_SKEW))) return false;
        if (!before(thisUpdate, at.minus(MAX_AGE))) return true;
        return !GoFmt.isZero(nextUpdate) && !after(thisUpdate, at);
    }

    /** Go validate.OCSPCertIDMatches. */
    static boolean ocspCertIdMatches(byte[] der, Cert cert, Cert issuer) {
        try {
            List<Asn1.Node> top = Asn1.children(Asn1.expect(Asn1.readNode(der, 0), Asn1.SEQUENCE, "OCSPResponse"));
            Asn1.Node st = Asn1.expect(Asn1.at(top, 0), Asn1.ENUMERATED, "status");
            if (st.length() != 1 || st.buf[st.vs] != 0) return false;
            List<Asn1.Node> rb = Asn1.children(Asn1.expect(Asn1.children(Asn1.expect(Asn1.at(top, 1), 0xa0, "responseBytes")).get(0), Asn1.SEQUENCE,
                "ResponseBytes"));
            Asn1.expect(Asn1.at(rb, 0), Asn1.OID, "responseType");
            byte[] resp = Asn1.expect(Asn1.at(rb, 1), Asn1.OCTET_STRING, "response").value();
            List<Asn1.Node> basic = Asn1.children(Asn1.expect(Asn1.readNode(resp, 0), Asn1.SEQUENCE, "BasicOCSPResponse"));
            List<Asn1.Node> tf = Asn1.children(Asn1.expect(Asn1.at(basic, 0), Asn1.SEQUENCE, "tbsResponseData"));
            int i = 0;
            if (Asn1.at(tf, i) != null && tf.get(i).tag == 0xa0) i++;
            if (Asn1.at(tf, i++) == null) return false;
            Asn1.expect(Asn1.at(tf, i++), Asn1.GENERALIZED_TIME, "producedAt");
            List<Asn1.Node> singles = Asn1.children(Asn1.expect(Asn1.at(tf, i), Asn1.SEQUENCE, "responses"));
            boolean found = false;
            for (Asn1.Node single : singles) {
                List<Asn1.Node> cid = Asn1.children(Asn1.expect(Asn1.children(Asn1.expect(single, Asn1.SEQUENCE, "SingleResponse")).get(0),
                    Asn1.SEQUENCE, "CertID"));
                String alg = Asn1.oid(Asn1.expect(Asn1.children(Asn1.expect(Asn1.at(cid, 0), Asn1.SEQUENCE, "hashAlgorithm")).get(0), Asn1.OID, "hash"));
                byte[] nameHash = Asn1.expect(Asn1.at(cid, 1), Asn1.OCTET_STRING, "issuerNameHash").value();
                byte[] keyHash = Asn1.expect(Asn1.at(cid, 2), Asn1.OCTET_STRING, "issuerKeyHash").value();
                if (!Asn1.intValue(Asn1.expect(Asn1.at(cid, 3), Asn1.INTEGER, "serial").value()).equals(cert.serial)) continue;
                String h = VCrypto.hashName(alg);
                if (h == null) return false;
                if (!Arrays.equals(nameHash, VCrypto.digest(h, issuer.rawSubject)) || !Arrays.equals(keyHash, VCrypto.digest(h, issuer.publicKeyBits))) {
                    return false;
                }
                found = true;
            }
            return found;
        } catch (RuntimeException e) {
            return false;
        }
    }

    // ── CRL ──

    static final class Crl {
        byte[] rawIssuer;
        byte[] tbs;
        Asn1.Node sigAlg;
        byte[] sig;
        Instant thisUpdate;
        Instant nextUpdate = Asn1.ZERO;
        byte[] authorityKeyId = new byte[0];
        final List<BigInteger> revokedSerials = new ArrayList<>();
        final List<Instant> revokedTimes = new ArrayList<>();
    }

    private static boolean isTime(Asn1.Node n) {
        return n != null && (n.tag == Asn1.UTC_TIME || n.tag == Asn1.GENERALIZED_TIME);
    }

    /** x509.ParseRevocationList subset; null when it does not parse. */
    static Crl parseCrl(byte[] der) {
        try {
            List<Asn1.Node> top = Asn1.children(Asn1.expect(Asn1.parseOne(der), Asn1.SEQUENCE, "CertificateList"));
            Asn1.Node tbs = Asn1.expect(Asn1.at(top, 0), Asn1.SEQUENCE, "TBSCertList");
            Asn1.Node sigAlg = Asn1.expect(Asn1.at(top, 1), Asn1.SEQUENCE, "sigAlg");
            Asn1.Node sigBits = Asn1.expect(Asn1.at(top, 2), Asn1.BIT_STRING, "sig");
            List<Asn1.Node> f = Asn1.children(tbs);
            int i = 0;
            if (Asn1.at(f, i) != null && f.get(i).tag == Asn1.INTEGER) i++;
            Asn1.expect(Asn1.at(f, i++), Asn1.SEQUENCE, "signature");
            Asn1.Node issuer = Asn1.expect(Asn1.at(f, i++), Asn1.SEQUENCE, "issuer");
            Asn1.Node tu = Asn1.at(f, i++);
            if (!isTime(tu)) return null;
            Crl c = new Crl();
            c.thisUpdate = Asn1.preciseTime(tu);
            if (isTime(Asn1.at(f, i))) c.nextUpdate = Asn1.preciseTime(f.get(i++));
            if (Asn1.at(f, i) != null && f.get(i).tag == Asn1.SEQUENCE) {
                for (Asn1.Node e : Asn1.children(f.get(i++))) {
                    List<Asn1.Node> p = Asn1.children(Asn1.expect(e, Asn1.SEQUENCE, "entry"));
                    BigInteger serial = Asn1.intValue(Asn1.expect(Asn1.at(p, 0), Asn1.INTEGER, "serial").value());
                    Asn1.Node t = Asn1.at(p, 1);
                    if (t == null) throw new Asn1.Error("entry time");
                    c.revokedSerials.add(serial);
                    c.revokedTimes.add(Asn1.preciseTime(t));
                }
            }
            if (Asn1.at(f, i) != null && f.get(i).tag == 0xa0) {
                for (Asn1.Node ext : Asn1.children(Asn1.expect(Asn1.children(f.get(i)).get(0), Asn1.SEQUENCE, "extensions"))) {
                    List<Asn1.Node> e = Asn1.children(ext);
                    if (!Asn1.oid(Asn1.expect(Asn1.at(e, 0), Asn1.OID, "extnID")).equals(OID_AKI)) continue;
                    byte[] v = Asn1.expect(e.get(e.size() - 1), Asn1.OCTET_STRING, "extnValue").value();
                    for (Asn1.Node k : Asn1.children(Asn1.parseOne(v))) {
                        if (k.tag == 0x80) {
                            c.authorityKeyId = k.value();
                            break;
                        }
                    }
                }
            }
            c.rawIssuer = issuer.raw();
            c.tbs = tbs.raw();
            c.sigAlg = sigAlg;
            byte[] sb = sigBits.value();
            if (sb.length == 0) return null;
            c.sig = Arrays.copyOfRange(sb, 1, sb.length);
            return c;
        } catch (RuntimeException e) {
            return null;
        }
    }

    /** Go x509 parent checks of CheckSignatureFrom for [usageBit] (cert sign 5, CRL sign 6). */
    static boolean parentMay(Cert parent, int usageBit) {
        return parent.mayIssue(usageBit);
    }

    /** Go RevocationList.CheckSignatureFrom (SHA-1 rejected). */
    static boolean crlSignedBy(Crl crl, Cert issuer) {
        if (!parentMay(issuer, Cert.KU_CRL_SIGN)) return false;
        try {
            if (SHA1_SIG.contains(Asn1.oid(Asn1.children(crl.sigAlg).get(0)))) return false;
            return VCrypto.verify(issuer, crl.sigAlg, crl.tbs, crl.sig);
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static byte[] subjectKeyId(Cert c) {
        byte[] v = c.extensionValue(Cert.OID_SKI);
        if (v == null) return new byte[0];
        try {
            Asn1.Node n = Asn1.parseOne(v);
            return n.tag == Asn1.OCTET_STRING ? n.value() : new byte[0];
        } catch (RuntimeException e) {
            return new byte[0];
        }
    }

    /** Go validate.CRLFor. */
    static boolean crlFor(Crl crl, Cert cert, Cert issuer) {
        if (!Arrays.equals(crl.rawIssuer, cert.rawIssuer) || !Arrays.equals(crl.rawIssuer, issuer.rawSubject)) return false;
        byte[] ski = subjectKeyId(issuer);
        if (crl.authorityKeyId.length > 0 && ski.length > 0 && !Arrays.equals(crl.authorityKeyId, ski)) return false;
        return crlSignedBy(crl, issuer);
    }

    /** Go validate.CRLListed: the revocation time, or null. */
    static Instant crlListed(Crl crl, Cert cert) {
        for (int i = 0; i < crl.revokedSerials.size(); i++) if (crl.revokedSerials.get(i).equals(cert.serial)) return crl.revokedTimes.get(i);
        return null;
    }

    // ── OCSP ──

    static final class OcspResp {
        String status;
        BigInteger serial;
        Instant thisUpdate;
        /** ZERO = absent. */
        Instant nextUpdate = Asn1.ZERO;
        Instant revokedAt;
        Cert certificate;
    }

    /** x/crypto/ocsp CreateRequest (SHA-1 CertID). */
    static byte[] ocspRequest(Cert c, Cert issuer) {
        byte[] certId = Der.seq(Der.seq(Der.oid(SHA1_OID), Der.nullValue()), Der.octets(VCrypto.digest("SHA-1", issuer.rawSubject)),
            Der.octets(VCrypto.digest("SHA-1", issuer.publicKeyBits)), Der.integer(c.serial));
        return Der.seq(Der.seq(Der.seq(Der.seq(certId))));
    }

    private static final String SHA1_OID = "1.3.14.3.2.26";

    private static final class OcspError extends RuntimeException {
        OcspError(String m) {
            super(m);
        }
    }

    /** TS parseOCSP: serial null = exactly one response; issuer null = no signature check. Throws on any failure. */
    static OcspResp parseOcsp(byte[] der, BigInteger serial, Cert issuer) {
        List<Asn1.Node> top = Asn1.children(Asn1.expect(Asn1.parseOne(der), Asn1.SEQUENCE, "OCSPResponse"));
        Asn1.Node st = Asn1.expect(Asn1.at(top, 0), Asn1.ENUMERATED, "status");
        if (st.length() == 0 || st.buf[st.vs] != 0) throw new OcspError("OCSP response status");
        List<Asn1.Node> rb = Asn1.children(Asn1.expect(Asn1.children(Asn1.expect(Asn1.at(top, 1), 0xa0, "responseBytes")).get(0), Asn1.SEQUENCE,
            "ResponseBytes"));
        if (!Asn1.oid(Asn1.expect(Asn1.at(rb, 0), Asn1.OID, "responseType")).equals(OID_OCSP_BASIC)) throw new OcspError("bad OCSP response type");
        List<Asn1.Node> basic = Asn1.children(Asn1.expect(Asn1.parseOne(Asn1.expect(Asn1.at(rb, 1), Asn1.OCTET_STRING, "response").value()),
            Asn1.SEQUENCE, "BasicOCSPResponse"));
        Asn1.Node tbs = Asn1.expect(Asn1.at(basic, 0), Asn1.SEQUENCE, "tbsResponseData");
        Asn1.Node sigAlg = Asn1.expect(Asn1.at(basic, 1), Asn1.SEQUENCE, "sigAlg");
        byte[] sb = Asn1.expect(Asn1.at(basic, 2), Asn1.BIT_STRING, "signature").value();
        byte[] sigBits = sb.length == 0 ? sb : Arrays.copyOfRange(sb, 1, sb.length);
        List<Asn1.Node> tf = Asn1.children(tbs);
        int i = 0;
        if (Asn1.at(tf, 0) != null && tf.get(0).tag == 0xa0) i++;
        Asn1.Node rid = Asn1.at(tf, i++);
        if (rid == null || (rid.tag != 0xa1 && rid.tag != 0xa2)) throw new OcspError("invalid responder id tag");
        i++; // producedAt
        List<Asn1.Node> responses = Asn1.children(Asn1.expect(Asn1.at(tf, i), Asn1.SEQUENCE, "responses"));
        List<Asn1.Node> single = null;
        if (serial != null) {
            if (responses.isEmpty()) throw new OcspError("OCSP response contains bad number of responses");
            for (Asn1.Node r : responses) {
                List<Asn1.Node> f = Asn1.children(r);
                List<Asn1.Node> cid = Asn1.children(f.get(0));
                if (Asn1.intValue(Asn1.expect(Asn1.at(cid, 3), Asn1.INTEGER, "serial").value()).equals(serial)) {
                    single = f;
                    break;
                }
            }
            if (single == null) throw new OcspError("no response matching the supplied certificate");
        } else {
            if (responses.size() != 1) throw new OcspError("OCSP response contains bad number of responses");
            single = Asn1.children(responses.get(0));
        }
        Cert certificate = null;
        Asn1.Node b3 = Asn1.at(basic, 3);
        if (b3 != null && b3.tag == 0xa0) {
            List<Asn1.Node> certs = Asn1.children(Asn1.expect(Asn1.children(b3).get(0), Asn1.SEQUENCE, "certs"));
            if (!certs.isEmpty()) certificate = VCrypto.cert(certs.get(0).raw());
        }
        if (certificate != null) {
            if (!VCrypto.verify(certificate, sigAlg, tbs.raw(), sigBits)) throw new OcspError("bad signature on embedded certificate");
            if (issuer != null && !(VCrypto.keyStrongEnough(issuer.publicKey()) && certificate.signedByAllowingSha1(issuer))) {
                throw new OcspError("bad OCSP signature");
            }
        } else if (issuer != null && !VCrypto.verify(issuer, sigAlg, tbs.raw(), sigBits)) {
            throw new OcspError("bad OCSP signature");
        }
        List<Asn1.Node> cid = Asn1.children(single.get(0));
        String hashAlg = Asn1.oid(Asn1.children(cid.get(0)).get(0));
        if (VCrypto.hashName(hashAlg) == null) throw new OcspError("unsupported issuer hash algorithm");
        Asn1.Node s = Asn1.at(single, 1);
        if (s == null) throw new OcspError("OCSP certStatus");
        OcspResp out = new OcspResp();
        out.status = s.tag == 0x80 ? "good" : s.tag == 0xa1 ? "revoked" : s.tag == 0x82 ? "unknown" : null;
        if (out.status == null) throw new OcspError("OCSP certStatus");
        if (out.status.equals("revoked")) out.revokedAt = Asn1.preciseTime(Asn1.expect(Asn1.at(Asn1.children(s), 0), Asn1.GENERALIZED_TIME, "revocationTime"));
        out.thisUpdate = Asn1.preciseTime(Asn1.expect(Asn1.at(single, 2), Asn1.GENERALIZED_TIME, "thisUpdate"));
        for (int k = 3; k < single.size(); k++) {
            Asn1.Node x = single.get(k);
            if (x.tag == 0xa0) out.nextUpdate = Asn1.preciseTime(Asn1.children(x).get(0));
            if (x.tag == 0xa1) {
                for (Asn1.Node ext : Asn1.children(Asn1.children(x).get(0))) {
                    List<Asn1.Node> e = Asn1.children(ext);
                    Asn1.Node c = Asn1.at(e, 1);
                    if (c != null && c.tag == Asn1.BOOLEAN && c.length() > 0 && c.buf[c.vs] != 0) throw new OcspError("unsupported critical extension");
                }
            }
        }
        out.serial = Asn1.intValue(Asn1.expect(Asn1.at(cid, 3), Asn1.INTEGER, "serial").value());
        out.certificate = certificate;
        return out;
    }

    /** a and b are the same certificate or the same subject + key. */
    static boolean sameCertKey(Cert a, Cert b) {
        return Arrays.equals(a.raw, b.raw) || (Arrays.equals(a.rawSubject, b.rawSubject) && Arrays.equals(a.rawSubjectPublicKeyInfo, b.rawSubjectPublicKeyInfo));
    }

    /** TS parseOCSPFrom: parseOcsp, or an issuer-signed response embedding the issuer's own certificate (RFC 6960 §4.2.2.2). */
    static OcspResp parseOcspFrom(byte[] der, BigInteger serial, Cert issuer) {
        try {
            return parseOcsp(der, serial, issuer);
        } catch (RuntimeException e) {
            OcspResp alt;
            try {
                alt = parseOcsp(der, serial, null);
            } catch (RuntimeException e2) {
                throw e;
            }
            if (alt.certificate != null && sameCertKey(alt.certificate, issuer) && ocspSignedBy(der, issuer)) return alt;
            throw e;
        }
    }

    private static boolean ocspSignedBy(byte[] der, Cert k) {
        try {
            List<Asn1.Node> top = Asn1.children(Asn1.parseOne(der));
            List<Asn1.Node> rb = Asn1.children(Asn1.children(top.get(1)).get(0));
            List<Asn1.Node> basic = Asn1.children(Asn1.parseOne(rb.get(1).value()));
            byte[] sb = basic.get(2).value();
            return sb.length > 0 && VCrypto.verify(k, basic.get(1), basic.get(0).raw(), Arrays.copyOfRange(sb, 1, sb.length));
        } catch (RuntimeException e) {
            return false;
        }
    }

    static boolean ocspFreshAt(OcspResp r, Instant at, Instant now) {
        return freshAt(r.thisUpdate, r.nextUpdate, at, now);
    }
}
