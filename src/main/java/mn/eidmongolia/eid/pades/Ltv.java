package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.LongConsumer;
import java.util.function.Supplier;

/** DSS payload of one signature (Go core.DSS). */
final class DssData {
    final List<byte[]> certs = new ArrayList<>();
    final List<byte[]> ocsps = new ArrayList<>();
    final List<byte[]> crls = new ArrayList<>();
    byte[] contents;
}

/**
 * A chain certificate is revoked by its issuer-signed OCSP response or CRL (Go `pades.ErrCertificateRevoked`). Final —
 * `complete` stops at once.
 */
final class CertificateRevoked extends IOException {
    final String ref;

    CertificateRevoked(String ref) {
        super("certificate revoked (" + ref + ")");
        this.ref = ref;
    }
}

/**
 * B-LT collection — Go reference `pades/ltv.go`: OCSP (SHA-1 CertID) and CRL (CDP) per chain certificate, checked for
 * signature/issuer, CertID, freshness at the current time; fail-closed; revoked → [CertificateRevoked].
 *
 * <p>Order by certificate role (Go `pades-golden-v11`, PROFILE.md §8): the first certificate of each chain (end entity —
 * signer, TSA) asks its OCSP first (full timeout, freshness/retry rule) and then its CRL. A CA certificate (every later
 * position) fetches its CRL first and sends no OCSP request at all when a valid CRL is obtained; only without one does it
 * fall back to its OCSP. A CA OCSP responder that accepts the connection and never answers then no longer stalls signing.
 * An interrupted caller gets {@link InterruptedIOException} (interrupt flag kept) instead of a missing-revocation error.
 */
final class Ltv {
    static final class NotFresh extends IOException {
        NotFresh(String msg) {
            super(msg);
        }
    }

    static final class Incomplete extends IOException {
        Incomplete(String msg) {
            super(msg);
        }
    }

    private static final long AFTER_TS_MS = 2_000L;
    private static final long WAIT_MAX_MS = 5_000L;
    private static final long RETRY_MS = 1_000L;

    private Ltv() {
    }

    /** Wait until 2 s after genTime (≤ 5 s), retry on a not-yet-fresh leaf OCSP every 1 s, total wait ≤ 5 s. */
    @SafeVarargs
    static DssData collectWithWait(Fetcher f, Supplier<Date> now, LongConsumer sleep, Date genTime, List<Cert> roots,
                                   List<Cert>... chains) throws IOException {
        long waited = 0;
        long d = Math.min((genTime.getTime() / 1000) * 1000 + AFTER_TS_MS - now.get().getTime(), WAIT_MAX_MS);
        while (true) {
            if (d > 0) {
                sleep.accept(d);
                waited += d;
            }
            try {
                return collect(f, now.get(), genTime, roots, chains);
            } catch (NotFresh e) {
                if (waited + RETRY_MS > WAIT_MAX_MS) throw e;
            }
            d = RETRY_MS;
        }
    }

    private static void add(List<byte[]> list, byte[] der) {
        for (byte[] x : list) if (Arrays.equals(x, der)) return;
        list.add(der);
    }

    @SafeVarargs
    static DssData collect(Fetcher f, Date now, Date after, List<Cert> roots, List<Cert>... chains) throws IOException {
        DssData d = new DssData();
        List<Cert> candidates = new ArrayList<>();
        for (List<Cert> ch : chains) candidates.addAll(ch);
        candidates.addAll(roots);
        Set<Cert> seen = new HashSet<>();
        for (List<Cert> ch : chains) {
            for (int i = 0; i < ch.size(); i++) {
                Cert c = ch.get(i);
                if (seen.contains(c) || roots.contains(c)) continue;
                seen.add(c);
                add(d.certs, c.raw);
                Cert issuer = null;
                for (Cert x : candidates) {
                    if (c.issuedBy(x)) {
                        issuer = x;
                        break;
                    }
                }
                if (issuer == null) throw new Incomplete("issuer of " + c.serialRef() + " not found");
                Date fresh = i == 0 ? after : null;
                Found r = new Found();
                if (i == 0) {
                    // End entity (signer / TSA leaf): OCSP first, full timeout, then the CRL — both embedded.
                    ocsp(f, c, issuer, now, fresh, d, r);
                    crls(f, c, issuer, now, d, r);
                } else {
                    // CA certificate: CRL first; no OCSP request at all when a valid CRL is obtained.
                    crls(f, c, issuer, now, d, r);
                    if (!r.ok) ocsp(f, c, issuer, now, null, d, r);
                }
                // An interrupted caller (DefaultHttp keeps the flag set) ends here, flag kept, instead of reading as
                // missing revocation data.
                if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException("LTV collection interrupted");
                boolean ok = r.ok;
                NotFresh freshErr = r.freshErr;
                if (!ok) {
                    if (freshErr != null) throw new NotFresh(freshErr.getMessage() + ": " + c.serialRef());
                    throw new Incomplete("no valid OCSP/CRL for " + c.serialRef());
                }
                if (i == 0 && after != null && freshErr != null && !c.ocspServers().isEmpty() && !hasFreshOcsp(d.ocsps, c, issuer, after)) {
                    throw new NotFresh(freshErr.getMessage() + ": " + c.serialRef());
                }
            }
        }
        return d;
    }

    /** Revocation evidence found for one certificate. */
    private static final class Found {
        boolean ok;
        NotFresh freshErr;
    }

    /** Go firstOCSP: the certificate's AIA OCSP URLs in order, first valid response; revoked → stop at once. */
    private static void ocsp(Fetcher f, Cert c, Cert issuer, Date now, Date fresh, DssData d, Found r) throws CertificateRevoked {
        for (String u : c.ocspServers()) {
            try {
                Object[] x = fetchOcsp(f, u, c, issuer, now, fresh);
                add(d.ocsps, (byte[]) x[0]);
                Ocsp.Response resp = (Ocsp.Response) x[1];
                if (resp.certificate != null && !resp.certificate.equals(issuer)) add(d.certs, resp.certificate.raw); // delegated responder
                r.ok = true;
                return;
            } catch (CertificateRevoked e) {
                throw e;
            } catch (NotFresh e) {
                r.freshErr = e;
            } catch (Exception e) {
                // next responder
            }
        }
    }

    /** Go validCRLs: every CDP CRL (in order) that covers [c]; listed → [CertificateRevoked]. */
    private static void crls(Fetcher f, Cert c, Cert issuer, Date now, DssData d, Found r) throws CertificateRevoked {
        for (String u : c.crlDistributionPoints()) {
            byte[] der;
            try {
                der = f.get(u);
            } catch (Exception e) {
                continue;
            }
            if (Crl.covers(der, c, issuer, now)) {
                add(d.crls, der);
                r.ok = true;
            }
        }
    }

    private static boolean hasFreshOcsp(List<byte[]> list, Cert c, Cert issuer, Date after) {
        for (byte[] der : list) {
            try {
                if (Ocsp.parseForCert(der, c, issuer).thisUpdate.after(after) && Ocsp.certIdMatches(der, c, issuer)) return true;
            } catch (Exception e) {
                // not this one
            }
        }
        return false;
    }

    /**
     * Go fetchOCSP: SHA-1 CertID request; signed by the issuer (or a delegated id-kp-OCSPSigning responder), CertID = this
     * certificate + issuer, revoked → [CertificateRevoked], good and fresh now, thisUpdate after [after] (when given).
     * Returns {der, Ocsp.Response}.
     */
    static Object[] fetchOcsp(Fetcher f, String url, Cert c, Cert issuer, Date now, Date after) throws IOException {
        byte[] der = f.post(url, "application/ocsp-request", Ocsp.request(c, issuer));
        Ocsp.Response resp = Ocsp.parseForCert(der, c, issuer);
        if (!Ocsp.responderOk(resp, issuer)) throw new IOException("OCSP responder EKU is not OCSPSigning");
        if (!Ocsp.certIdMatches(der, c, issuer)) throw new IOException("OCSP CertID is not this certificate's");
        if (resp.status == Ocsp.REVOKED) throw new CertificateRevoked(c.serialRef());
        if (resp.status != Ocsp.GOOD || !Revocation.freshAt(resp.thisUpdate, resp.nextUpdate, now, now)) {
            throw new IOException("OCSP " + c.serialRef() + ": not good or not fresh");
        }
        if (after != null && !resp.thisUpdate.after(after)) throw new NotFresh("OCSP thisUpdate is not after the timestamp");
        return new Object[] {der, resp};
    }
}

/** Freshness of revocation evidence — Go `validate.FreshAt`. */
final class Revocation {
    /** thisUpdate may be at most this long before the check time when nextUpdate does not cover it. */
    static final long MAX_AGE_MS = 24 * 3600_000L;
    /** Responder ↔ checker clock tolerance. */
    static final long CLOCK_SKEW_MS = 5 * 60_000L;

    private Revocation() {
    }

    static boolean freshAt(Date thisUpdate, Date nextUpdate, Date at, Date now) {
        if (thisUpdate.getTime() > now.getTime() + CLOCK_SKEW_MS) return false;
        if (nextUpdate != null && nextUpdate.getTime() < at.getTime() - CLOCK_SKEW_MS) return false;
        if (thisUpdate.getTime() >= at.getTime() - MAX_AGE_MS) return true;
        return nextUpdate != null && thisUpdate.getTime() <= at.getTime();
    }
}

/** CRL (RFC 5280 §5.1) — Go `validate.CRLFor` / `CRLListed` / `crlCovers`. */
final class Crl {
    private Crl() {
    }

    static final class Parsed {
        final byte[] rawIssuer;
        final byte[] authorityKeyId;
        final Date thisUpdate;
        final Date nextUpdate;
        final List<BigInteger> revoked;
        final byte[] tbs;
        final String sigOid;
        final byte[] signature;

        Parsed(byte[] rawIssuer, byte[] authorityKeyId, Date thisUpdate, Date nextUpdate, List<BigInteger> revoked, byte[] tbs,
               String sigOid, byte[] signature) {
            this.rawIssuer = rawIssuer;
            this.authorityKeyId = authorityKeyId;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.revoked = revoked;
            this.tbs = tbs;
            this.sigOid = sigOid;
            this.signature = signature;
        }
    }

    static Parsed parse(byte[] der) {
        try {
            Der.Tlv top = Der.parse(der);
            Tsa.check(top.tag == Der.SEQUENCE && top.end == der.length, "CRL");
            List<Der.Tlv> list = top.children();
            Tsa.check(list.size() == 3 && list.get(0).tag == Der.SEQUENCE && list.get(2).tag == Der.BIT_STRING, "CRL");
            Der.Tlv bits = list.get(2);
            Tsa.check(bits.length() >= 1 && bits.buf[bits.valueStart] == 0, "CRL");
            List<Der.Tlv> t = list.get(0).children();
            int i = t.get(0).tag == Der.INTEGER ? 1 : 0;
            i++; // signature algorithm
            Der.Tlv issuer = t.get(i++);
            Tsa.check(issuer.tag == Der.SEQUENCE, "CRL");
            Date thisUpdate = Asn1Time.parse(t.get(i++));
            Date next = null;
            if (i < t.size() && (t.get(i).tag == Der.UTC_TIME || t.get(i).tag == Der.GENERALIZED_TIME)) next = Asn1Time.parse(t.get(i++));
            List<BigInteger> revoked = new ArrayList<>();
            if (i < t.size() && t.get(i).tag == Der.SEQUENCE) {
                for (Der.Tlv e : t.get(i++).children()) {
                    Der.Tlv s = e.child(0);
                    Tsa.check(s.tag == Der.INTEGER, "CRL");
                    revoked.add(s.bigInt());
                }
            }
            byte[] aki = new byte[0];
            if (i < t.size() && t.get(i).tag == Der.ctx(0)) {
                for (Der.Tlv ext : t.get(i).child(0).children()) {
                    List<Der.Tlv> p = ext.children();
                    if (!p.get(0).oid().equals(Cert.OID_AKI)) continue;
                    for (Der.Tlv k : Der.parse(p.get(p.size() - 1).value()).children()) {
                        if (k.tag == Der.ctx(0, false)) {
                            aki = k.value();
                            break;
                        }
                    }
                }
            }
            return new Parsed(issuer.encoded(), aki, thisUpdate, next, revoked, list.get(0).encoded(), list.get(1).child(0).oid(),
                Arrays.copyOfRange(bits.buf, bits.valueStart + 1, bits.end));
        } catch (Exception e) {
            return null;
        }
    }

    /** Go `validate.CRLFor`: the CRL of [cert]'s issuer — issuer names, AKI = SKI (when both present), issuer signature. */
    static boolean isFor(Parsed crl, Cert cert, Cert issuer) {
        if (!Arrays.equals(crl.rawIssuer, cert.rawIssuer) || !Arrays.equals(crl.rawIssuer, issuer.rawSubject)) return false;
        byte[] ski = issuer.subjectKeyId();
        if (crl.authorityKeyId.length > 0 && ski.length > 0 && !Arrays.equals(crl.authorityKeyId, ski)) return false;
        return issuer.mayIssue(Cert.KU_CRL_SIGN) && Sig.verifyOid(crl.sigOid, issuer.publicKey(), crl.tbs, crl.signature);
    }

    /** Go crlCovers: a CRL of [c]'s issuer with a nextUpdate, fresh now, [c] not listed (listed → [CertificateRevoked]). */
    static boolean covers(byte[] der, Cert c, Cert issuer, Date now) throws CertificateRevoked {
        Parsed crl = parse(der);
        if (crl == null || !isFor(crl, c, issuer)) return false;
        for (BigInteger s : crl.revoked) if (s.equals(c.serial)) throw new CertificateRevoked(c.serialRef());
        return crl.nextUpdate != null && Revocation.freshAt(crl.thisUpdate, crl.nextUpdate, now, now);
    }
}

/** OCSP (RFC 6960) request/response — x/crypto/ocsp semantics the Go reference uses. */
final class Ocsp {
    static final int GOOD = 0;
    static final int REVOKED = 1;
    private static final String OID_SHA1 = "1.3.14.3.2.26";
    private static final String OID_BASIC = "1.3.6.1.5.5.7.48.1.1";

    private Ocsp() {
    }

    static final class Response {
        final int status;
        final Date thisUpdate;
        final Date nextUpdate;
        final Cert certificate;

        Response(int status, Date thisUpdate, Date nextUpdate, Cert certificate) {
            this.status = status;
            this.thisUpdate = thisUpdate;
            this.nextUpdate = nextUpdate;
            this.certificate = certificate;
        }
    }

    /** OCSPRequest { tbsRequest { requestList { Request { CertID(SHA-1 + NULL) } } } } (x/crypto CreateRequest). */
    static byte[] request(Cert c, Cert issuer) {
        byte[] certId = Der.seq(Der.seq(Der.oid(OID_SHA1), Der.nullValue()), Der.octets(Cms.sha1(issuer.rawSubject)),
            Der.octets(Cms.sha1(issuer.publicKeyBits)), Der.integer(c.serial));
        return Der.seq(Der.seq(Der.seq(Der.seq(certId))));
    }

    /** x/crypto ParseResponseForCert: signature by issuer or by an included cert the issuer signed; the cert's SingleResponse. */
    static Response parseForCert(byte[] der, Cert c, Cert issuer) {
        List<Der.Tlv> top = Der.parse(der).children();
        byte[] st = top.get(0).value();
        Tsa.check(top.get(0).tag == Der.ENUMERATED && st.length == 1 && st[0] == 0, "OCSP response status");
        Der.Tlv rb = top.get(1).child(0);
        Tsa.check(rb.child(0).oid().equals(OID_BASIC), "not a basic OCSP response");
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
            Tsa.check(responder.equals(issuer) || responder.signedBy(issuer), "OCSP responder not issued by the issuer");
            Tsa.check(Sig.verifyOid(sigOid, responder.publicKey(), tbs.encoded(), sig), "OCSP signature");
        } else {
            Tsa.check(Sig.verifyOid(sigOid, issuer.publicKey(), tbs.encoded(), sig), "OCSP signature");
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
    static boolean certIdMatches(byte[] der, Cert c, Cert issuer) {
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
    static boolean responderOk(Response r, Cert issuer) {
        return r.certificate == null || r.certificate.equals(issuer) || r.certificate.extKeyUsage().contains(Cert.OID_KP_OCSP_SIGNING);
    }
}
