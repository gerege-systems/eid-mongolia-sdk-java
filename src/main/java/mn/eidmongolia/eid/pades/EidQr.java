package mn.eidmongolia.eid.pades;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Instant;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * «Миний QR» (contract {@code myqr-2026-10-26}): the citizen shows {@code EIDMN-QR1:<token>} in the eID app → the RP
 * starts the session with the raw RP-API ({@code POST /authentication/qr}) → the citizen approves with PIN2 → the RP
 * receives a PS256 JWS signed with the citizen's own QUALIFIED SIGN key ({@code x5c}) → {@link #verify} (contract §6.1)
 * returns «Миний мэдээлэл» (the app's dict as is, payload order). Same rules as the Go / TS / .NET SDKs
 * ({@code myqr_vectors.json}). No RP-API client here — only parsing and verification.
 *
 * <p>Thread-safe, no global mutable state. Network only for the default revocation check (the leaf's AIA OCSP).
 */
public final class EidQr {
    /** Prefix of the citizen app's QR: {@code EIDMN-QR1:<token>}. */
    public static final String PREFIX = "EIDMN-QR1:";
    /** Expected {@code iss} of the presentation JWS. */
    public static final String DEFAULT_ISSUER = "https://ca.eidmongolia.mn";
    /** Subject Key Identifier of eID Mongolia Issuing CA (04) — the default {@link Trust#allowedIssuerSkis()}. */
    public static final String CITIZEN_ISSUING_CA_SKI = "b8a37f2c64ad677912db7d9e34f246358a2fb909";
    /** JWS {@code typ}. */
    public static final String JWS_TYPE = "eidmn-myqr+jwt";

    static final int MAX_JWS = 524288;
    static final int MAX_FIELDS = 128;
    static final int MAX_KEY_CHARS = 64;
    static final int MAX_VALUE_BYTES = 2048;
    static final int MAX_PHOTO_BYTES = 153600;
    static final long MAX_AGE_SECONDS = 300;
    static final long SKEW_SECONDS = 60;
    static final int MIN_RSA_BITS = 2048;

    private static final String OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3";
    private static final String OID_QC_COMPLIANCE = "0.4.0.1862.1.1";
    private static final String OID_KEY_USAGE = "2.5.29.15";

    private static final Pattern TOKEN_RE = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern SEG_RE = Pattern.compile("^[A-Za-z0-9_-]+$");
    private static final Pattern SOURCE_RE = Pattern.compile("^[a-z0-9_-]{1,32}$");

    private EidQr() {
    }

    /** {@link #parse} result: the 43-character token and the trimmed QR string. */
    public record Parsed(String token, String qr) {
    }

    /**
     * What the presentation must match.
     *
     * @param rpUuid    your RP UUID ({@code aud}, case-insensitive)
     * @param sessionId the RP-API session id ({@code sid})
     * @param nonce     the nonce you sent (exact)
     * @param issuer    null = {@link #DEFAULT_ISSUER}
     * @param now       null = now
     */
    public record Expect(String rpUuid, String sessionId, String nonce, String issuer, Instant now) {
        public Expect(String rpUuid, String sessionId, String nonce) {
            this(rpUuid, sessionId, nonce, null, null);
        }
    }

    /** Revocation status of the leaf: "good" | "revoked" | "unknown" (an exception counts as "unknown"). */
    @FunctionalInterface
    public interface RevocationCheck {
        String status(X509Certificate leaf, X509Certificate issuer) throws Exception;
    }

    /**
     * Trust settings; every null field has a default.
     *
     * @param anchors            trusted roots (null/empty = the embedded Mongolian National Root CA)
     * @param intermediates      intermediate CAs (null = the embedded 02–05); x5c[1] is always only an intermediate candidate
     * @param allowedIssuerSkis  SKI (hex, ":" allowed) of the CA that issued the leaf (null/empty = {@link #CITIZEN_ISSUING_CA_SKI})
     * @param revocation         null = the leaf's AIA OCSP (hard-fail)
     * @param revocationSoftFail true accepts "unknown"
     */
    public record Trust(List<X509Certificate> anchors, List<X509Certificate> intermediates, List<String> allowedIssuerSkis,
                        RevocationCheck revocation, boolean revocationSoftFail) {
        public static final Trust DEFAULT = new Trust(null, null, null, null, false);
    }

    /** The citizen who signed (from the certificate subject). */
    public record Signer(X509Certificate certificate, String etsi, String givenName, String surname, String commonName) {
    }

    /**
     * A verified «Миний QR» presentation.
     *
     * @param jws         the raw compact JWS (audit / dispute)
     * @param claimsJson  the payload JSON as signed (iss, sub, aud, rp_name, sid, nonce, iat, exp, statement, data)
     * @param data        «Миний мэдээлэл» {@code fields} in payload order, keys as is
     * @param source      {@code data.source} (dan, passport, citizenid …)
     * @param photo       face JPEG, or null
     * @param signedAt    {@code iat}
     * @param sha256      hex SHA-256(signingInput) — equals the CA audit {@code qrsha}
     */
    public record Result(String jws, String claimsJson, List<Map.Entry<String, String>> data, String source, byte[] photo,
                         Signer signer, Instant signedAt, String sha256) {
    }

    /** Trims ASCII white space and checks {@code EIDMN-QR1:} + a 43-character base64url token; else QR_FORMAT_INVALID. */
    public static Parsed parse(String scanned) {
        String s = trimAscii(scanned == null ? "" : scanned);
        if (!s.startsWith(PREFIX) || !TOKEN_RE.matcher(s.substring(PREFIX.length())).matches()) {
            throw new EidQrException(EidQrException.FORMAT_INVALID, "not an eID «My QR»");
        }
        return new Parsed(s.substring(PREFIX.length()), s);
    }

    private static String trimAscii(String s) {
        int a = 0;
        int b = s.length();
        while (a < b && " \t\n\r\f\u000b".indexOf(s.charAt(a)) >= 0) a++;
        while (b > a && " \t\n\r\f\u000b".indexOf(s.charAt(b - 1)) >= 0) b--;
        return s.substring(a, b);
    }

    private static EidQrException err(String code, String reason) {
        return new EidQrException(code, reason);
    }

    /** {@link #verify(String, Expect, Trust)} with {@link Trust#DEFAULT}. */
    public static Result verify(String jws, Expect expect) {
        return verify(jws, expect, Trust.DEFAULT);
    }

    /**
     * Verifies the presentation JWS per contract §6.1, stopping at the first failure with an {@link EidQrException} code.
     * Verifies the received bytes — never re-serialises. Network only for the default revocation check.
     */
    public static Result verify(String jws, Expect expect, Trust trust) {
        if (expect == null) throw new NullPointerException("expect");
        Trust t = trust == null ? Trust.DEFAULT : trust;
        Instant now = expect.now() != null ? expect.now() : Instant.now();

        // 1. Structure.
        if (jws == null || jws.isEmpty() || jws.length() > MAX_JWS) throw err(EidQrException.JWS_MALFORMED, "JWS empty or too long");
        String[] seg = jws.split("\\.", -1);
        if (seg.length != 3) throw err(EidQrException.JWS_MALFORMED, "not a compact JWS");
        for (String x : seg) if (!SEG_RE.matcher(x).matches()) throw err(EidQrException.JWS_MALFORMED, "not a compact JWS");

        // 2–3. Header.
        byte[][] ders = parseHeader(seg[0]);
        Cert leaf;
        Cert inter;
        try {
            leaf = Cert.parse(ders[0]);
            inter = Cert.parse(ders[1]);
        } catch (Exception e) {
            throw err(EidQrException.HEADER_INVALID, "x5c is not a certificate");
        }

        // 4. Chain + leaf profile.
        Cert issuer = checkChain(leaf, inter, t, now);

        // 5. Revocation.
        String status;
        try {
            status = t.revocation() != null ? t.revocation().status(leaf.x509, issuer.x509) : defaultRevocation(leaf, issuer);
        } catch (Exception e) {
            status = "unknown";
        }
        if ("revoked".equals(status)) throw err(EidQrException.CERT_REVOKED, "certificate revoked (" + leaf.serialRef() + ")");
        if (!"good".equals(status) && !t.revocationSoftFail()) {
            throw err(EidQrException.REVOCATION_UNKNOWN, "revocation status unknown (" + leaf.serialRef() + ")");
        }

        // 6. Signature: RSASSA-PSS SHA-256, MGF1-SHA-256, salt 32.
        byte[] signingInput = (seg[0] + "." + seg[1]).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = b64UrlOrNull(seg[2]);
        boolean ok = false;
        if (sig != null && leaf.isRsa()) {
            try {
                Signature v = Signature.getInstance("RSASSA-PSS");
                v.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
                v.initVerify(leaf.publicKey());
                v.update(signingInput);
                ok = v.verify(sig);
            } catch (Exception e) {
                ok = false;
            }
        }
        if (!ok) throw err(EidQrException.SIGNATURE_INVALID, "signature does not verify");

        // 7–12. Payload.
        byte[] pb = b64UrlOrNull(seg[1]);
        if (pb == null) throw err(EidQrException.JWS_MALFORMED, "payload is not base64url");
        Json.Obj c = objectOrNull(pb);
        if (c == null) throw err(EidQrException.JWS_MALFORMED, "payload is not a JSON object");
        String etsiAttr = leaf.subjectAttr(Cert.OID_SERIAL_NUMBER);
        String etsi = etsiAttr == null ? "" : etsiAttr;
        Checked ck = checkClaims(c, expect, etsi, now);
        Signer signer = new Signer(leaf.x509, etsi, opt(leaf, "2.5.4.42"), opt(leaf, "2.5.4.4"), opt(leaf, "2.5.4.3"));
        String sha = Text.hex(Cms.sha256(signingInput));
        return new Result(jws, new String(pb, StandardCharsets.UTF_8), ck.data, ck.source, ck.photo, signer, Instant.ofEpochSecond(ck.iat), sha);
    }

    private static String opt(Cert c, String oid) {
        String v = c.subjectAttr(oid);
        return v == null || v.isEmpty() ? null : v;
    }

    private static byte[][] parseHeader(String seg0) {
        byte[] hb = b64UrlOrNull(seg0);
        if (hb == null) throw err(EidQrException.HEADER_INVALID, "header is not base64url");
        Json.Obj h = objectOrNull(hb);
        if (h == null) throw err(EidQrException.HEADER_INVALID, "header is not a JSON object");
        List<String> names = new ArrayList<>(h.keys);
        Collections.sort(names);
        if (!names.equals(Arrays.asList("alg", "typ", "x5c"))) throw err(EidQrException.HEADER_INVALID, "header members are not exactly alg, typ, x5c");
        if (!"PS256".equals(h.get("alg"))) throw err(EidQrException.HEADER_INVALID, "alg is not PS256");
        if (!JWS_TYPE.equals(h.get("typ"))) throw err(EidQrException.HEADER_INVALID, "typ is not " + JWS_TYPE);
        Object x5c = h.get("x5c");
        if (!(x5c instanceof List) || ((List<?>) x5c).size() != 2) throw err(EidQrException.HEADER_INVALID, "x5c is not an array of 2");
        byte[][] ders = new byte[2][];
        for (int i = 0; i < 2; i++) {
            Object e = ((List<?>) x5c).get(i);
            if (!(e instanceof String) || ((String) e).isEmpty()) throw err(EidQrException.HEADER_INVALID, "x5c element empty or not a string");
            ders[i] = stdB64OrNull((String) e);
            if (ders[i] == null) throw err(EidQrException.HEADER_INVALID, "x5c is not standard base64");
        }
        return ders;
    }

    private static List<Cert> certs(List<X509Certificate> l) {
        List<Cert> out = new ArrayList<>();
        for (X509Certificate x : l) {
            try {
                out.add(Cert.parse(x.getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("trust certificate", e);
            }
        }
        return out;
    }

    private static boolean validWithSkew(Cert c, Instant now) {
        long n = now.toEpochMilli();
        return n >= c.x509.getNotBefore().getTime() - SKEW_SECONDS * 1000 && n <= c.x509.getNotAfter().getTime() + SKEW_SECONDS * 1000;
    }

    /**
     * Builds leaf → x5c[1] / intermediates → a trust anchor (subject/issuer, signature, CA + keyCertSign), checks every
     * element's validity with ±60 s and the leaf profile; returns the leaf's issuer.
     */
    private static Cert checkChain(Cert leaf, Cert inter, Trust t, Instant now) {
        List<Cert> anchors = t.anchors() != null && !t.anchors().isEmpty() ? certs(t.anchors()) : List.of(EidChain.nationalRoot());
        List<Cert> pool = new ArrayList<>();
        pool.add(inter);
        pool.addAll(t.intermediates() != null ? certs(t.intermediates()) : EidChain.intermediates());
        List<Cert> path = new ArrayList<>();
        path.add(leaf);
        Cert cur = leaf;
        boolean anchored = false;
        for (int step = 0; step < 8 && !anchored; step++) {
            Cert root = null;
            for (Cert a : anchors) {
                if (cur.issuedBy(a)) {
                    root = a;
                    break;
                }
            }
            if (root != null) {
                if (!root.equals(cur)) path.add(root);
                anchored = true;
                break;
            }
            Cert next = null;
            for (Cert c : pool) {
                if (!path.contains(c) && cur.issuedBy(c)) {
                    next = c;
                    break;
                }
            }
            if (next == null) break;
            path.add(next);
            cur = next;
            if (anchors.contains(cur)) anchored = true;
        }
        if (!anchored || path.size() < 2) throw err(EidQrException.CHAIN_INVALID, "the chain does not reach a trusted root");
        for (Cert c : path) {
            if (!validWithSkew(c, now)) throw err(EidQrException.CHAIN_INVALID, "certificate not valid now (" + c.serialRef() + ")");
        }
        Cert issuer = path.get(1);
        if (leaf.isCa()) throw err(EidQrException.CHAIN_INVALID, "the leaf is a CA certificate");
        boolean[] ku = leaf.x509.getKeyUsage();
        if (leaf.extensionValue(OID_KEY_USAGE) == null || ku == null || ku.length < 2 || !ku[1]) {
            throw err(EidQrException.CHAIN_INVALID, "KeyUsage without contentCommitment");
        }
        if (!isQualified(leaf)) throw err(EidQrException.CHAIN_INVALID, "certificate is not QUALIFIED (no QcCompliance)");
        List<String> allowed = new ArrayList<>();
        List<String> src = t.allowedIssuerSkis() != null && !t.allowedIssuerSkis().isEmpty() ? t.allowedIssuerSkis() : List.of(CITIZEN_ISSUING_CA_SKI);
        for (String s : src) allowed.add(s.replace(":", "").toLowerCase(Locale.ROOT));
        byte[] ski = issuer.subjectKeyId();
        if (ski.length == 0 || !allowed.contains(Text.hex(ski))) throw err(EidQrException.CHAIN_INVALID, "issuing CA not allowed");
        if (!(leaf.publicKey() instanceof RSAPublicKey) || ((RSAPublicKey) leaf.publicKey()).getModulus().bitLength() < MIN_RSA_BITS) {
            throw err(EidQrException.CHAIN_INVALID, "not an RSA ≥ 2048 key");
        }
        return issuer;
    }

    /** qcStatements contains QcCompliance (QUALIFIED/QSCD). Broken → false. */
    static boolean isQualified(Cert c) {
        byte[] v = c.extensionValue(OID_QC_STATEMENTS);
        if (v == null) return false;
        try {
            Der.Tlv seq = Der.parse(v);
            if (seq.tag != Der.SEQUENCE || seq.end != v.length) return false;
            boolean compliance = false;
            for (Der.Tlv st : seq.children()) {
                if (st.tag != Der.SEQUENCE) return false;
                Der.Tlv oid = st.child(0);
                if (oid.tag != Der.OID) return false;
                compliance |= oid.oid().equals(OID_QC_COMPLIANCE);
            }
            return compliance;
        } catch (Exception e) {
            return false;
        }
    }

    /** Default revocation: the leaf's AIA OCSP (CertID, signature, responder, freshness). No answer → "unknown". */
    static String defaultRevocation(Cert leaf, Cert issuer) {
        Fetcher f = new Fetcher(DefaultHttp.INSTANCE);
        for (String url : leaf.ocspServers()) {
            try {
                byte[] der = f.post(url, "application/ocsp-request", Ocsp.request(leaf, issuer));
                Ocsp.Response resp = Ocsp.parseForCert(der, leaf, issuer);
                if (!Ocsp.responderOk(resp, issuer) || !Ocsp.certIdMatches(der, leaf, issuer)) continue;
                if (resp.status == Ocsp.REVOKED) return "revoked";
                Date n = new Date();
                if (resp.status == Ocsp.GOOD && Revocation.freshAt(resp.thisUpdate, resp.nextUpdate, n, n)) return "good";
            } catch (Exception e) {
                // next responder
            }
        }
        return "unknown";
    }

    private static final class Checked {
        long iat;
        List<Map.Entry<String, String>> data;
        String source;
        byte[] photo;
    }

    private static Checked checkClaims(Json.Obj c, Expect expect, String etsi, Instant now) {
        String iss = expect.issuer() == null || expect.issuer().isEmpty() ? DEFAULT_ISSUER : expect.issuer();
        if (!iss.equals(str(c, "iss"))) throw err(EidQrException.CLAIMS_INVALID, "iss mismatch");
        String sub = str(c, "sub");
        if (sub == null || etsi.isEmpty() || !sub.equals(etsi)) throw err(EidQrException.CLAIMS_INVALID, "sub does not match the certificate serialNumber");
        String rpName = str(c, "rp_name");
        String statement = str(c, "statement");
        String nonce = str(c, "nonce");
        String sid = str(c, "sid");
        String aud = str(c, "aud");
        if (rpName == null || statement == null || nonce == null || sid == null || aud == null) {
            throw err(EidQrException.CLAIMS_INVALID, "rp_name/statement/nonce/sid/aud are not strings");
        }
        Long iat = integer(c, "iat");
        Long exp = integer(c, "exp");
        if (iat == null || exp == null) throw err(EidQrException.CLAIMS_INVALID, "iat/exp are not integers");
        if (!statement.equals(statement(rpName))) throw err(EidQrException.CLAIMS_INVALID, "statement does not match the template");
        // 8–10.
        if (expect.rpUuid() == null || expect.rpUuid().isEmpty()
            || !aud.toLowerCase(Locale.ROOT).equals(expect.rpUuid().toLowerCase(Locale.ROOT))) {
            throw err(EidQrException.AUDIENCE_MISMATCH, "aud (RP UUID) mismatch");
        }
        if (expect.sessionId() == null || expect.sessionId().isEmpty() || !sid.equals(expect.sessionId())) {
            throw err(EidQrException.SESSION_MISMATCH, "sid mismatch");
        }
        if (expect.nonce() == null || expect.nonce().isEmpty() || !nonce.equals(expect.nonce())) {
            throw err(EidQrException.NONCE_MISMATCH, "nonce mismatch");
        }
        // 11.
        long span = exp - iat;
        if (span <= 0 || span > MAX_AGE_SECONDS) throw err(EidQrException.CLAIMS_INVALID, "exp − iat is not in (0, 300]");
        long nowMs = now.toEpochMilli();
        if (iat > (nowMs / 1000.0) + SKEW_SECONDS) throw err(EidQrException.NOT_YET_VALID, "iat in the future");
        if (!(nowMs < (exp + SKEW_SECONDS) * 1000)) throw err(EidQrException.EXPIRED, "presentation expired");
        // 12.
        Object d = c.get("data");
        if (d == null) throw err(EidQrException.DATA_INVALID, "data missing");
        Checked out = checkData(d);
        out.iat = iat;
        return out;
    }

    static String statement(String rpName) {
        return "Та " + rpName + "-д «Миний мэдээлэл» хэсгийн бүх мэдээллийг хуваалцах гэж байна";
    }

    private static Checked checkData(Object d) {
        if (!(d instanceof Json.Obj)) throw err(EidQrException.DATA_INVALID, "data is not an object");
        Json.Obj o = (Json.Obj) d;
        String source = null;
        Object fields = null;
        String photoB64 = null;
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < o.keys.size(); i++) {
            String name = o.keys.get(i);
            Object v = o.values.get(i);
            if (!seen.add(name)) throw err(EidQrException.DATA_INVALID, "duplicate member in data");
            switch (name) {
                case "source":
                    if (!(v instanceof String)) throw err(EidQrException.DATA_INVALID, "source is not a string");
                    source = (String) v;
                    break;
                case "fields":
                    fields = v;
                    break;
                case "photo":
                    if (!(v instanceof String)) throw err(EidQrException.DATA_INVALID, "photo is not a string");
                    photoB64 = (String) v;
                    break;
                default:
                    throw err(EidQrException.DATA_INVALID, "extra member in data");
            }
        }
        if (source == null || !SOURCE_RE.matcher(source).matches()) throw err(EidQrException.DATA_INVALID, "source invalid");
        if (!(fields instanceof Json.Obj)) throw err(EidQrException.DATA_INVALID, "fields is not an object");
        Json.Obj f = (Json.Obj) fields;
        List<Map.Entry<String, String>> list = new ArrayList<>();
        Set<String> keys = new HashSet<>();
        for (int i = 0; i < f.keys.size(); i++) {
            if (list.size() >= MAX_FIELDS) throw err(EidQrException.DATA_INVALID, "fields > 128");
            String key = f.keys.get(i);
            Object v = f.values.get(i);
            if (!(v instanceof String)) throw err(EidQrException.DATA_INVALID, "value is not a string");
            String val = (String) v;
            if (!wellFormed(key) || !wellFormed(val)) throw err(EidQrException.DATA_INVALID, "invalid UTF-16");
            if (!keys.add(key)) throw err(EidQrException.DATA_INVALID, "duplicate key in fields");
            if (!keyOk(key)) throw err(EidQrException.DATA_INVALID, "key invalid (1–64 code points, no control characters)");
            if (val.getBytes(StandardCharsets.UTF_8).length > MAX_VALUE_BYTES || val.indexOf('\0') >= 0) {
                throw err(EidQrException.DATA_INVALID, "value > 2048 bytes or invalid");
            }
            list.add(new AbstractMap.SimpleImmutableEntry<>(key, val));
        }
        byte[] photo = null;
        if (photoB64 != null) {
            photo = stdB64OrNull(photoB64);
            if (photo == null || photo.length > MAX_PHOTO_BYTES || photo.length < 3 || photo[0] != (byte) 0xFF || photo[1] != (byte) 0xD8
                || photo[2] != (byte) 0xFF) {
                throw err(EidQrException.DATA_INVALID, "photo is not a strict base64 JPEG ≤ 150 KiB");
            }
        }
        // §1.3: empty fields require a photo.
        if (list.isEmpty() && photo == null) throw err(EidQrException.DATA_INVALID, "fields empty and no photo");
        Checked out = new Checked();
        out.data = Collections.unmodifiableList(list);
        out.source = source;
        out.photo = photo;
        return out;
    }

    private static boolean wellFormed(String s) {
        return Text.validSurrogates(s);
    }

    private static boolean keyOk(String k) {
        int n = 0;
        for (int i = 0; i < k.length(); ) {
            int r = k.codePointAt(i);
            if (r <= 0x1F || (r >= 0x7F && r <= 0x9F)) return false;
            n++;
            i += Character.charCount(r);
        }
        return n >= 1 && n <= MAX_KEY_CHARS;
    }

    private static String str(Json.Obj o, String name) {
        Object v = o.get(name);
        return v instanceof String ? (String) v : null;
    }

    private static Long integer(Json.Obj o, String name) {
        Object v = o.get(name);
        return v instanceof Json.Num ? ((Json.Num) v).exactLong() : null;
    }

    private static Json.Obj objectOrNull(byte[] b) {
        try {
            Object v = Json.parse(b);
            return v instanceof Json.Obj ? (Json.Obj) v : null;
        } catch (Exception e) {
            return null;
        }
    }

    static byte[] b64UrlOrNull(String s) {
        if (!SEG_RE.matcher(s).matches() || s.length() % 4 == 1) return null;
        try {
            return Base64.getUrlDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Strict standard base64 (padded, no line breaks, canonical): re-encoding must give the same string. */
    static byte[] stdB64OrNull(String s) {
        if (s.length() % 4 != 0) return null;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            boolean ok = (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=';
            if (!ok) return null;
        }
        byte[] b;
        try {
            b = Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
        return Base64.getEncoder().encodeToString(b).equals(s) ? b : null;
    }

    /** Certificate serial as lowercase hex without leading zeros (test stubs key revocation by it). */
    static String serialHex(X509Certificate c) {
        BigInteger s = c.getSerialNumber();
        return s.toString(16);
    }
}
