package mn.eidmongolia.eid;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Ocsp;
import mn.eidmongolia.eid.internal.Text;

/**
 * A {@link RevocationChecker} that asks the OCSP responder named in the certificate's AIA (Go {@code NewOCSPChecker},
 * TS {@code ocspRevocationChecker}; the eID portal's EID_OCSP rules):
 *
 * <ul>
 *   <li>good → {@link RevocationStatus#GOOD}, cached for min(cache TTL = 5 min, the response's nextUpdate);
 *   <li>revoked, and also unknown (the issuer never issued that serial — somebody else's certificate) →
 *       {@link RevocationStatus#REVOKED};
 *   <li>no acceptable answer (no AIA, no issuer, timeout, HTTP ≠ 200, a response whose signature / serial / time does
 *       not match) → {@link EidException.Ocsp} with its {@link EidException.Ocsp.Kind} — status UNKNOWN; the
 *       validator's {@link RevocationMode} decides.
 * </ul>
 *
 * <p>The response must be signed by the issuer, or by a responder certificate the issuer issued with id-kp-OCSPSigning,
 * valid now and embedded in the response (RFC 6960 §4.2.2.2); be about this serial; have thisUpdate in
 * [now − 48 h, now + 5 min] and a nextUpdate (when present) not before now; be at most 16 KiB; come with HTTP 200
 * (redirects are not followed). Each request has 2 s, all responders together 3 s — the citizen is waiting.
 *
 * <p>This is NOT the PAdES LTV rule (which collects evidence with a 24 h freshness window); the two stay separate.
 * Thread-safe; share one instance (it holds the cache).
 */
public final class OcspRevocationChecker implements RevocationChecker {
    /** One request's deadline. */
    public static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(2);
    /** All responders of one check together. */
    public static final Duration TOTAL_TIMEOUT = Duration.ofSeconds(3);
    /** The default cache lifetime of a GOOD answer (also capped by the response's nextUpdate). */
    public static final Duration DEFAULT_CACHE_TTL = Duration.ofMinutes(5);
    /** The response size limit. */
    public static final int MAX_RESPONSE_BYTES = 16 << 10;
    /** Responder ↔ RP clock tolerance for thisUpdate in the future. */
    public static final Duration CLOCK_SKEW = Duration.ofMinutes(5);
    /**
     * The oldest acceptable thisUpdate. The CA signs every response fresh (thisUpdate = now, nextUpdate = +24 h); the
     * limit stops a "good" fetched before a revocation from being replayed over plain HTTP.
     */
    public static final Duration MAX_AGE = Duration.ofHours(48);
    private static final int CACHE_MAX = 1024;
    private static final String OID_KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";

    private final EidTransport transport;
    private final Clock clock;
    private final Duration ttl;
    private final Consumer<OcspObservation> observer;
    private final boolean bindCertId;
    private final Map<String, Instant> cache = new HashMap<>();

    private OcspRevocationChecker(Builder b) {
        this.transport = b.transport != null ? b.transport : defaultTransport();
        this.clock = b.clock != null ? b.clock : Clock.systemUTC();
        this.ttl = b.cacheTtl == null || b.cacheTtl.isZero() ? DEFAULT_CACHE_TTL : b.cacheTtl;
        this.observer = b.observer;
        this.bindCertId = b.bindCertId;
    }

    /** A checker with the defaults (own HTTP/1.1 client: 2 s connect, no redirects). */
    public static OcspRevocationChecker create() {
        return builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    private static EidTransport defaultTransport() {
        return JdkHttpTransport.of(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(REQUEST_TIMEOUT).build());
    }

    /**
     * One check (Go {@code ocspChecker.check}).
     *
     * @return GOOD or REVOKED
     * @throws EidException.Ocsp no acceptable answer (status UNKNOWN)
     */
    @Override
    public RevocationStatus check(X509Certificate cert, X509Certificate issuer) {
        if (cert == null || issuer == null) {
            EidException.Ocsp e = new EidException.Ocsp(EidException.Ocsp.Kind.NO_ISSUER, "", 0, "", null);
            emit(new OcspObservation(RevocationStatus.UNKNOWN, "", Duration.ZERO, false, e));
            throw e;
        }
        Cert leaf;
        Cert iss;
        try {
            leaf = Cert.parse(cert.getEncoded());
            iss = Cert.parse(issuer.getEncoded());
        } catch (CertificateEncodingException | RuntimeException x) {
            EidException.Ocsp e = new EidException.Ocsp(EidException.Ocsp.Kind.PARSE, "", 0, "гэрчилгээ задарсангүй", x);
            emit(new OcspObservation(RevocationStatus.UNKNOWN, "", Duration.ZERO, false, e));
            throw e;
        }
        // Cross-SDK hardening (stricter than Go / TS): the given issuer must have signed the leaf — checked before the cache
        // and before any network call, so a wrong issuer never yields a GOOD bound to somebody else's CertID.
        if (!leaf.issuedBy(iss)) {
            EidException.Ocsp e = new EidException.Ocsp(EidException.Ocsp.Kind.NO_ISSUER, "", 0, "гэрчилгээг өгсөн issuer гаргаагүй", null);
            emit(new OcspObservation(RevocationStatus.UNKNOWN, "", Duration.ZERO, false, e));
            throw e;
        }
        String key = Text.hex(EidCrypto.digest("SHA-256", iss.raw)).substring(0, 16) + ":" + leaf.serial.toString(16);
        Instant hit;
        synchronized (cache) {
            hit = cache.get(key);
        }
        if (hit != null && clock.instant().isBefore(hit)) {
            // The observer runs outside the cache lock (a slow / re-entrant observer must not block other checks).
            emit(new OcspObservation(RevocationStatus.GOOD, "", Duration.ZERO, true, null));
            return RevocationStatus.GOOD;
        }
        // The total time across every AIA URL — the citizen is waiting on a poll.
        long start = System.nanoTime();
        Asked a = new Asked();
        try {
            ask(leaf, iss, start + TOTAL_TIMEOUT.toNanos(), a);
        } catch (EidException.Ocsp e) {
            emit(new OcspObservation(RevocationStatus.UNKNOWN, a.responder, Duration.ofNanos(System.nanoTime() - start), false, e));
            throw e;
        }
        Duration took = Duration.ofNanos(System.nanoTime() - start);
        // Only GOOD is cached: revoked is final, and unknown must not lock out a freshly issued certificate. Lifetime =
        // min(TTL, nextUpdate − now) — never beyond the responder's own validity.
        if (a.status == RevocationStatus.GOOD && !ttl.isNegative()) {
            Instant now = clock.instant();
            Instant exp = now.plus(ttl);
            if (a.nextUpdate != null && a.nextUpdate.toInstant().isBefore(exp)) exp = a.nextUpdate.toInstant();
            if (exp.isAfter(now)) {
                synchronized (cache) {
                    if (cache.size() >= CACHE_MAX) cache.clear();
                    cache.put(key, exp);
                }
            }
        }
        emit(new OcspObservation(a.status, a.responder, took, false, null));
        return a.status;
    }

    private void emit(OcspObservation o) {
        if (observer != null) observer.accept(o);
    }

    private static final class Asked {
        RevocationStatus status;
        Date nextUpdate;
        String responder = "";
    }

    /** Go {@code ask}: the AIA URLs in order; the answering URL, or the last reason. */
    private void ask(Cert leaf, Cert issuer, long deadline, Asked out) {
        byte[] req;
        try {
            req = Ocsp.request(leaf, issuer);
        } catch (RuntimeException e) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.NO_ISSUER, "", 0, "", e);
        }
        EidException.Ocsp last = new EidException.Ocsp(EidException.Ocsp.Kind.NO_RESPONDER, "", 0, "", null);
        for (String raw : leaf.ocspServers()) {
            URI u;
            try {
                u = new URI(raw);
            } catch (URISyntaxException e) {
                last = new EidException.Ocsp(EidException.Ocsp.Kind.NO_RESPONDER, "", 0, "OCSP URL дэмжигдэхгүй", null);
                continue;
            }
            String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
            if (!scheme.equals("http") && !scheme.equals("https")) {
                last = new EidException.Ocsp(EidException.Ocsp.Kind.NO_RESPONDER, "", 0, "OCSP URL дэмжигдэхгүй", null);
                continue;
            }
            out.responder = u.toString();
            byte[] der;
            Ocsp.Parsed resp;
            try {
                der = post(u, out.responder, req, deadline);
                resp = verify(der, leaf, issuer, out.responder);
            } catch (EidException.Ocsp e) {
                last = e;
                continue;
            }
            // Revoked, and Unknown (the issuer does not know the serial) → REVOKED.
            out.status = resp.status == Ocsp.GOOD ? RevocationStatus.GOOD : RevocationStatus.REVOKED;
            out.nextUpdate = resp.nextUpdate;
            return;
        }
        throw last;
    }

    private byte[] post(URI u, String responder, byte[] body, long deadline) {
        long left = deadline - System.nanoTime();
        if (left <= 0) throw new EidException.Ocsp(EidException.Ocsp.Kind.TIMEOUT, responder, 0, "нийт хугацаа дууссан", null);
        Duration t = Duration.ofNanos(Math.min(REQUEST_TIMEOUT.toNanos(), left));
        Map<String, String> h = new LinkedHashMap<>();
        h.put("Content-Type", "application/ocsp-request");
        h.put("Accept", "application/ocsp-response");
        EidHttpResponse res;
        try {
            res = transport.send(new EidHttpRequest("POST", u, h, body, t, MAX_RESPONSE_BYTES));
        } catch (HttpTimeoutException | SocketTimeoutException e) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.TIMEOUT, responder, 0, "", e);
        } catch (InterruptedIOException e) {
            Thread.currentThread().interrupt();
            throw new EidException.Ocsp(EidException.Ocsp.Kind.TIMEOUT, responder, 0, "interrupt", e);
        } catch (IOException | RuntimeException e) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.NETWORK, responder, 0, e.getClass().getSimpleName(), e);
        }
        if (res == null) throw new EidException.Ocsp(EidException.Ocsp.Kind.NETWORK, responder, 0, "хариу алга", null);
        if (res.status() != 200) throw new EidException.Ocsp(EidException.Ocsp.Kind.HTTP_STATUS, responder, res.status(), "HTTP " + res.status(), null);
        String cl = res.header("Content-Length");
        boolean tooLarge = res.body().length > MAX_RESPONSE_BYTES;
        if (cl != null) {
            try {
                tooLarge |= Long.parseLong(cl.trim()) > MAX_RESPONSE_BYTES;
            } catch (NumberFormatException ignored) {
                // judged by the body read
            }
        }
        if (tooLarge) throw new EidException.Ocsp(EidException.Ocsp.Kind.HTTP_STATUS, responder, res.status(), "хариу хэт том", null);
        return res.body();
    }

    private static EidException.Ocsp.Kind kindOf(String parseKind) {
        switch (parseKind) {
            case Ocsp.KIND_RESPONDER_STATUS:
                return EidException.Ocsp.Kind.RESPONDER_STATUS;
            case Ocsp.KIND_SIGNATURE:
                return EidException.Ocsp.Kind.SIGNATURE;
            case Ocsp.KIND_INVALID:
                return EidException.Ocsp.Kind.INVALID;
            default:
                return EidException.Ocsp.Kind.PARSE;
        }
    }

    /** Go ocsp.go {@code verify}. */
    private Ocsp.Parsed verify(byte[] der, Cert leaf, Cert issuer, String responder) {
        Ocsp.Parsed resp;
        try {
            resp = Ocsp.parseResponseForCert(der, leaf, issuer);
        } catch (Ocsp.ParseException e) {
            // RFC 6960 §4.2.2.2: a response the issuer signed itself is valid. When it embeds the issuer's OWN certificate
            // x/crypto/ocsp demands that the embedded certificate be signed by the issuer and says «bad signature» — if
            // the embedded certificate IS the issuer (raw, or subject + SPKI), check the response with the issuer's key.
            Ocsp.Parsed alt = null;
            try {
                alt = Ocsp.parseResponseForCert(der, leaf, null);
            } catch (Ocsp.ParseException ignored) {
                // the first error stands
            }
            if (alt != null && alt.certificate != null && Ocsp.sameCertKey(alt.certificate, issuer) && alt.signedBy(issuer)) {
                resp = alt;
            } else {
                throw new EidException.Ocsp(kindOf(e.kind), responder, 0, e.getMessage(), e);
            }
        }
        Instant now = clock.instant();
        Cert rc = resp.certificate;
        if (rc != null && !Ocsp.sameCertKey(rc, issuer)) {
            if (!rc.extKeyUsage().contains(OID_KP_OCSP_SIGNING)) {
                throw new EidException.Ocsp(EidException.Ocsp.Kind.SIGNATURE, responder, 0, "responder-ийн EKU OCSPSigning биш", null);
            }
            if (now.isBefore(rc.x509.getNotBefore().toInstant()) || now.isAfter(rc.x509.getNotAfter().toInstant())) {
                throw new EidException.Ocsp(EidException.Ocsp.Kind.SIGNATURE, responder, 0, "responder-ийн гэрчилгээ хугацаандаа биш", null);
            }
        }
        Cert signer = rc != null ? rc : issuer;
        if (signer.isRsa() && signer.rsaBits() < ResponseValidator.MIN_RSA_BITS) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.SIGNATURE, responder, 0, "responder-ийн RSA түлхүүр 2048 битээс бага", null);
        }
        if (resp.serial == null || !resp.serial.equals(leaf.serial)) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.INVALID, responder, 0, "хариу өөр serial-ийн тухай", null);
        }
        if (bindCertId && !Ocsp.certIdMatches(der, leaf, issuer)) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.INVALID, responder, 0, "CertID энэ гэрчилгээ/олгогчийнх биш", null);
        }
        Instant tu = resp.thisUpdate.toInstant();
        if (tu.isAfter(now.plus(CLOCK_SKEW)) || tu.isBefore(now.minus(MAX_AGE))) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.INVALID, responder, 0, "thisUpdate хүлээн авах хүрээнээс гадуур", null);
        }
        if (resp.nextUpdate != null && resp.nextUpdate.toInstant().isBefore(now)) {
            throw new EidException.Ocsp(EidException.Ocsp.Kind.INVALID, responder, 0, "хариу хуучирсан (nextUpdate өнгөрсөн)", null);
        }
        return resp;
    }

    /** {@link OcspRevocationChecker} configuration; unset values take the defaults. */
    public static final class Builder {
        private EidTransport transport;
        private Clock clock;
        private Duration cacheTtl;
        private Consumer<OcspObservation> observer;
        private boolean bindCertId = true;

        private Builder() {
        }

        /**
         * The HTTP transport (proxy, tests). It must not follow redirects (the responder is the URL in the CA's
         * certificate; a 302 over plain HTTP is somebody else's). null = an own HTTP/1.1 {@link JdkHttpTransport}.
         */
        public Builder transport(EidTransport v) {
            transport = v;
            return this;
        }

        /** The clock for freshness and the cache (tests). null = the system clock. */
        public Builder clock(Clock v) {
            clock = v;
            return this;
        }

        /**
         * How long a GOOD answer is cached at most (also capped by the response's nextUpdate). null / zero = 5 min;
         * negative = no cache.
         */
        public Builder cacheTtl(Duration v) {
            cacheTtl = v;
            return this;
        }

        /**
         * Called after every check (cache hits too) — metrics / audit. No personal data (no serial, no name). Called
         * synchronously: keep it fast, never throw.
         */
        public Builder observer(Consumer<OcspObservation> v) {
            observer = v;
            return this;
        }

        /**
         * true (the default) also requires every SingleResponse for the serial to carry the issuer's CertID issuerNameHash /
         * issuerKeyHash (the PAdES LTV / «My QR» binding) — stricter than the Go / TS checkers, which compare the serial
         * only; false restores their rule.
         */
        public Builder bindCertId(boolean v) {
            bindCertId = v;
            return this;
        }

        public OcspRevocationChecker build() {
            return new OcspRevocationChecker(this);
        }
    }

    /**
     * One check's outcome for {@link Builder#observer} (Go {@code OCSPObservation}).
     *
     * @param status GOOD / REVOKED, or UNKNOWN when there was no answer
     * @param responder the URL that answered (or was tried last); "" for a cache hit / no AIA
     * @param duration the network time (zero for a cache hit)
     * @param cached answered from the cache
     * @param error why there was no answer; null otherwise
     */
    public record OcspObservation(RevocationStatus status, String responder, Duration duration, boolean cached,
        EidException.Ocsp error) {
        public OcspObservation {
            Objects.requireNonNull(status, "status");
        }
    }
}
