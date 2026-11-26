package mn.eidmongolia.eid;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The eID Mongolia RP-API client (Go {@code eid.Client}, TS {@code EidClient}) — server side only.
 *
 * <pre>{@code
 * EidClient eid = EidClient.builder(new Credentials(rpUuid, "Интернэт банк", apiSecret))
 *     .transport(JdkHttpTransport.create(sslContext)) // mTLS, optional
 *     .language("en")
 *     .build();
 * SessionTtl ttl = eid.auth().sessionTtl();
 * }</pre>
 *
 * <p>Calls are blocking (fine on virtual threads); {@link Thread#interrupt()} cancels a call in flight
 * ({@link EidException.Network#cancelled()}). Thread-safe — share one instance.
 *
 * <p>In progress: this release has the transport, configuration, errors, routes, wire types, discovery and the
 * crypto helpers ({@link Acsp}, {@link DeviceLink}, {@link EidCrypto}); the auth / sign / session / validator services
 * follow.
 */
public final class EidClient {
    /** The official RP-API host (all RPs since 2026-09-28, no /v3); mTLS RPs too. */
    public static final String DEFAULT_BASE_URL = "https://rp.eidmongolia.mn";
    /** The default per-call timeout. */
    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(15);
    /** The default PDF registration timeout (the CA checks CMS + TSA + LTV), below the CA's nginx proxy_read_timeout. */
    public static final Duration DEFAULT_PDF_TIMEOUT = Duration.ofSeconds(80);
    /**
     * The CA's default SIGNATURE / CERTIFICATE_CHOICE session lifetime (600 s, adjustable by the CA admin to
     * 60–1800 s). Used only when an older CA's start response has no expiresAt.
     */
    public static final Duration DEFAULT_SIGN_SESSION_TTL = Duration.ofSeconds(600);

    /** Old (0.2.x TS) shape: the ca. host with /v3 — a clear error instead of a silent 404. */
    private static final Set<String> LEGACY_HOSTS = Set.of("ca.eidmongolia.mn", "e-id.mn", "www.e-id.mn");

    private final RpHttp http;
    private final Credentials credentials;
    private final CertificateLevel defaultCertificateLevel;
    private final Duration pdfTimeout;
    private final Duration signSessionTtl;
    private final AuthService auth;

    private EidClient(Builder b) {
        if (b.credentials.apiSecret().isEmpty()) throw new IllegalArgumentException("eid: Credentials.apiSecret шаардлагатай");
        String base = resolveBaseUrl(b.baseUrl);
        Duration t = positiveOr(b.timeout, DEFAULT_TIMEOUT);
        this.credentials = b.credentials;
        this.defaultCertificateLevel = b.defaultCertificateLevel == null ? CertificateLevel.QUALIFIED : b.defaultCertificateLevel;
        this.pdfTimeout = positiveOr(b.pdfTimeout, DEFAULT_PDF_TIMEOUT);
        this.signSessionTtl = positiveOr(b.signSessionTtl, DEFAULT_SIGN_SESSION_TTL);
        EidTransport tr = b.transport == null ? JdkHttpTransport.create() : b.transport;
        this.http = new RpHttp(base, b.credentials.apiSecret(), t, tr, b.language == null ? "" : b.language.trim());
        this.auth = new AuthService(http);
    }

    private static Duration positiveOr(Duration d, Duration def) {
        return d == null || d.isZero() || d.isNegative() ? def : d;
    }

    public static Builder builder(Credentials credentials) {
        return new Builder(credentials);
    }

    /** Authentication (discovery sessionTtl in this release). */
    public AuthService auth() {
        return auth;
    }

    /** Credentials.rpName — the RP name shown on the citizen's phone. */
    public String rpName() {
        return credentials.rpName();
    }

    /** The resolved base URL (no trailing "/"). */
    public String baseUrl() {
        return http.base;
    }

    public CertificateLevel defaultCertificateLevel() {
        return defaultCertificateLevel;
    }

    public Duration timeout() {
        return http.timeout;
    }

    public Duration pdfTimeout() {
        return pdfTimeout;
    }

    public Duration signSessionTtl() {
        return signSessionTtl;
    }

    /** The Accept-Language value sent with every call; "" = none (the server uses mn). */
    public String language() {
        return http.lang;
    }

    RpHttp http() {
        return http;
    }

    Credentials credentials() {
        return credentials;
    }

    /**
     * When a session from a start response expires: the time BEFORE the request was sent + ttl (ttl ≤ 0 →
     * {@link #DEFAULT_SIGN_SESSION_TTL}) — never later than the CA's own value (Go {@code SessionExpiry}). For the RP
     * UI's countdown only; the final word is GET /session (TIMEOUT).
     */
    public static Instant sessionExpiry(Instant sentAt, Duration ttl) {
        return sentAt.plus(positiveOr(ttl, DEFAULT_SIGN_SESSION_TTL));
    }

    /**
     * Validates a base URL and trims trailing "/" (null / "" = {@link #DEFAULT_BASE_URL}); Go {@code ResolveBaseURL}.
     * https only — http only for localhost / loopback (the API secret never travels in clear text); the old ca. host
     * (which had /v3) is a clear error.
     *
     * @throws IllegalArgumentException when the URL is not acceptable
     */
    public static String resolveBaseUrl(String baseUrl) {
        String raw = baseUrl == null ? "" : baseUrl.strip();
        if (raw.isEmpty()) raw = DEFAULT_BASE_URL;
        int end = raw.length();
        while (end > 0 && raw.charAt(end - 1) == '/') end--;
        raw = raw.substring(0, end);
        URI u;
        try {
            u = new URI(raw);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("eid: BaseURL буруу URL: " + raw);
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String authority = u.getRawAuthority();
        if ((!scheme.equals("https") && !scheme.equals("http")) || authority == null || authority.substring(authority.lastIndexOf('@') + 1).isEmpty()) {
            throw new IllegalArgumentException("eid: BaseURL буруу URL: " + raw);
        }
        String host = hostname(authority);
        if (scheme.equals("http") && !isLoopback(host)) {
            throw new IllegalArgumentException("eid: BaseURL https байх ёстой (http зөвхөн localhost/loopback): " + raw);
        }
        String path = u.getRawPath() == null ? "" : u.getRawPath();
        if (LEGACY_HOSTS.contains(host) && path.isEmpty()) {
            throw new IllegalArgumentException("eid: RP-API " + host + "-аас " + DEFAULT_BASE_URL + " руу шилжсэн (/v3-гүй) — BaseURL-ийг "
                + DEFAULT_BASE_URL + " болгоно уу (эсвэл хоосон орхи)");
        }
        return raw;
    }

    /** Go {@code url.URL.Hostname}: userinfo and port dropped, IPv6 brackets removed. */
    static String hostname(String authority) {
        String a = authority.substring(authority.lastIndexOf('@') + 1);
        if (a.startsWith("[")) {
            int i = a.indexOf(']');
            return i < 0 ? a.substring(1) : a.substring(1, i);
        }
        int c = a.lastIndexOf(':');
        return c < 0 ? a : a.substring(0, c);
    }

    private static final Pattern IPV4 = Pattern.compile("(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})\\.(0|[1-9][0-9]{0,2})");
    private static final Pattern IPV6_CHARS = Pattern.compile("[0-9A-Fa-f:.]+");

    /**
     * localhost or a loopback IP literal (127.0.0.0/8, ::1, ::ffff:127.x) — Go {@code isLoopback}. Never resolves DNS:
     * only literals are parsed.
     */
    static boolean isLoopback(String host) {
        if (host.equalsIgnoreCase("localhost")) return true;
        Matcher m = IPV4.matcher(host);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) if (Integer.parseInt(m.group(i)) > 255) return false;
            return m.group(1).equals("127");
        }
        if (host.indexOf(':') >= 0 && IPV6_CHARS.matcher(host).matches()) {
            try {
                return InetAddress.getByName("[" + host + "]").isLoopbackAddress(); // bracketed: literal only, no DNS
            } catch (UnknownHostException e) {
                return false;
            }
        }
        return false;
    }

    /** {@link EidClient} configuration. Unset values take the defaults. */
    public static final class Builder {
        private final Credentials credentials;
        private String baseUrl;
        private CertificateLevel defaultCertificateLevel;
        private Duration timeout;
        private Duration pdfTimeout;
        private Duration signSessionTtl;
        private String language;
        private EidTransport transport;

        private Builder(Credentials credentials) {
            this.credentials = Objects.requireNonNull(credentials, "credentials");
        }

        /** The FULL RP-API base URL; the SDK only appends paths. null / "" = {@link #DEFAULT_BASE_URL}. */
        public Builder baseUrl(String v) {
            baseUrl = v;
            return this;
        }

        /** The default certLevel of every auth/sign. null = QUALIFIED. */
        public Builder defaultCertificateLevel(CertificateLevel v) {
            defaultCertificateLevel = v;
            return this;
        }

        /** The per-call timeout (whole exchange). null / ≤ 0 = 15 s. Long-poll and PDF use their own. */
        public Builder timeout(Duration v) {
            timeout = v;
            return this;
        }

        /** The PDF registration timeout. null / ≤ 0 = 80 s. */
        public Builder pdfTimeout(Duration v) {
            pdfTimeout = v;
            return this;
        }

        /** The sign / certificate-choice lifetime for an older CA without expiresAt. null / ≤ 0 = 600 s. */
        public Builder signSessionTtl(Duration v) {
            signSessionTtl = v;
            return this;
        }

        /** Accept-Language for human-readable texts ("mn" | "en"). null / "" = not sent (server mn). */
        public Builder language(String v) {
            language = v;
            return this;
        }

        /** The HTTP transport (mTLS: {@code JdkHttpTransport.create(sslContext)}). null = {@link JdkHttpTransport#create()}. */
        public Builder transport(EidTransport v) {
            transport = v;
            return this;
        }

        /**
         * @throws IllegalArgumentException empty API secret or an unacceptable base URL
         */
        public EidClient build() {
            return new EidClient(this);
        }
    }
}
