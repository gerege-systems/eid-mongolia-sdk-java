package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** RFC 3161 client — Go reference `pades/tsa.go` (request bytes per `pades/WIRE.md`). */
final class Tsa {
    private static final long MAX_SKEW_MS = 10 * 60_000L;

    private Tsa() {
    }

    static final class Token {
        final byte[] raw;
        final Date genTime;
        final List<Cert> certificates;

        Token(byte[] raw, Date genTime, List<Cert> certificates) {
            this.raw = raw;
            this.genTime = genTime;
            this.certificates = certificates;
        }
    }

    /** TimeStampReq { v1, messageImprint {sha256 + NULL, hash}, nonce, certReq TRUE } (digitorus Request.Marshal). */
    static byte[] request(byte[] hash, BigInteger nonce) {
        return Der.seq(
            Der.integer(1),
            Der.seq(Der.seq(Der.oid(Cms.OID_SHA256), Der.nullValue()), Der.octets(hash)),
            Der.integer(nonce),
            Der.bool(true));
    }

    static Token timestamp(Fetcher f, String url, byte[] signature, List<Cert> roots, List<Cert> inter, Date now, byte[] nonceBytes)
        throws IOException {
        byte[] sum = Cms.sha256(signature);
        BigInteger nonce = new BigInteger(1, nonceBytes);
        byte[] body = f.post(url, "application/timestamp-query", request(sum, nonce));
        List<Der.Tlv> parts = Der.parse(body).children();
        int status = parts.get(0).child(0).bigInt().intValue();
        check(status == 0 || status == 1, "TSA status " + status);
        check(parts.size() >= 2, "TSA response without token");
        byte[] tokenDer = parts.get(1).encoded();
        Cms.Parsed p = Cms.parse(tokenDer);
        byte[] tst = p.eContent;
        check(tst != null, "token without TSTInfo");
        check(p.signerCount == 1 && p.signer != null, "token signer");
        check(Cms.verify(p, tst), "token signature");
        List<Der.Tlv> info = Der.parse(tst).children();
        Der.Tlv imprint = info.get(2);
        check(imprint.child(0).child(0).oid().equals(Cms.OID_SHA256) && Arrays.equals(imprint.child(1).value(), sum),
            "timestamp hash does not match");
        Date genTime = Asn1Time.parse(info.get(4));
        BigInteger tokenNonce = null;
        for (int i = 5; i < info.size(); i++) {
            if (info.get(i).tag == Der.INTEGER) {
                tokenNonce = info.get(i).bigInt();
                break;
            }
        }
        check(nonce.equals(tokenNonce), "nonce mismatch");
        Cert signer = p.signer;
        check(signer.isTsaSigningCert(), "TSA signer EKU is not critical {timeStamping}");
        List<Cert> pool = new ArrayList<>(p.certificates);
        pool.addAll(inter);
        check(Chain.verify(signer, roots, pool, genTime), "TSA certificate chain");
        check(Math.abs(now.getTime() - genTime.getTime()) <= MAX_SKEW_MS, "TSA genTime too far from local time");
        check(!p.certificates.isEmpty(), "token without certificates");
        return new Token(tokenDer, genTime, p.certificates);
    }

    static void check(boolean ok, String msg) {
        if (!ok) throw new IllegalArgumentException(msg);
    }
}

/** ASN.1 time → Date (UTCTime / GeneralizedTime, `Z` or ±hhmm, optional fraction truncated to ms). */
final class Asn1Time {
    private static final Pattern UTC = Pattern.compile("^(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(?:[.,](\\d+))?(Z|[+-]\\d{4})$");
    private static final Pattern GEN = Pattern.compile("^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(?:[.,](\\d+))?(Z|[+-]\\d{4})$");

    private Asn1Time() {
    }

    static Date parse(Der.Tlv t) {
        String s = new String(t.value(), StandardCharsets.US_ASCII);
        boolean utc = t.tag == Der.UTC_TIME;
        Matcher m = (utc ? UTC : GEN).matcher(s);
        if (!m.matches()) throw new IllegalArgumentException("ASN.1 time " + s);
        int year = Integer.parseInt(m.group(1));
        if (utc) year += year < 50 ? 2000 : 1900;
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        c.clear();
        c.set(year, Integer.parseInt(m.group(2)) - 1, Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
            Integer.parseInt(m.group(5)), m.group(6) == null ? 0 : Integer.parseInt(m.group(6)));
        String frac = (m.group(7) == null ? "" : m.group(7)) + "000";
        c.set(Calendar.MILLISECOND, Integer.parseInt(frac.substring(0, 3)));
        long ms = c.getTimeInMillis();
        String z = m.group(8);
        if (!z.equals("Z")) {
            int sign = z.charAt(0) == '-' ? -1 : 1;
            ms -= sign * (Integer.parseInt(z.substring(1, 3)) * 3600_000L + Integer.parseInt(z.substring(3, 5)) * 60_000L);
        }
        return new Date(ms);
    }
}

/**
 * Minimal path validation — Go `x509.Verify` (verifyTSAChain, KeyUsages timeStamping): subject/issuer + signature, every
 * certificate valid at [at], each issuer a CA allowed to sign certificates, pathLenConstraint and the EKU of every
 * issuer (empty, anyExtendedKeyUsage or timeStamping).
 */
final class Chain {
    private Chain() {
    }

    private static boolean ekuOk(Cert c) {
        List<String> e = c.extKeyUsage();
        return e.isEmpty() || e.contains(Cert.OID_ANY_EKU) || e.contains(Cert.OID_KP_TIMESTAMPING);
    }

    static boolean verify(Cert leaf, List<Cert> roots, List<Cert> pool, Date at) {
        Cert cur = leaf;
        int below = 0; // CA certificates between the leaf and the next issuer (Go numIntermediates)
        Set<Cert> used = new HashSet<>();
        for (int step = 0; step < 8; step++) {
            if (!cur.validAt(at)) return false;
            if (roots.contains(cur)) return true;
            for (Cert r : roots) {
                if (cur.issuedBy(r) && r.validAt(at) && r.allowsPath(below) && ekuOk(r)) return true;
            }
            Cert next = null;
            for (Cert c : pool) {
                if (!c.equals(cur) && !used.contains(c) && cur.issuedBy(c) && c.isCa() && c.allowsPath(below) && ekuOk(c)) {
                    next = c;
                    break;
                }
            }
            if (next == null) return false;
            used.add(cur);
            cur = next;
            below++;
        }
        return false;
    }
}
