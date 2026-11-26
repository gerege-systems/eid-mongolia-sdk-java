package mn.eidmongolia.eid.login;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import mn.eidmongolia.eid.AuthOptions;
import mn.eidmongolia.eid.CertificateLevel;
import mn.eidmongolia.eid.DeviceLink;
import mn.eidmongolia.eid.DeviceLinkInput;
import mn.eidmongolia.eid.DeviceLinkSession;
import mn.eidmongolia.eid.DeviceLinkSessionType;
import mn.eidmongolia.eid.DeviceLinkType;
import mn.eidmongolia.eid.EidClient;
import mn.eidmongolia.eid.EidException;
import mn.eidmongolia.eid.FlowType;
import mn.eidmongolia.eid.Interaction;
import mn.eidmongolia.eid.NotificationSession;
import mn.eidmongolia.eid.Person;
import mn.eidmongolia.eid.RevocationChecker;
import mn.eidmongolia.eid.RevocationMode;
import mn.eidmongolia.eid.RevocationOutcome;
import mn.eidmongolia.eid.OcspRevocationChecker;
import mn.eidmongolia.eid.SessionResult;
import mn.eidmongolia.eid.ValidateAuthOptions;
import mn.eidmongolia.eid.ValidationReasons;
import mn.eidmongolia.eid.VerifiedIdentity;

/**
 * «Sign in with eID» button backend — framework neutral (Go {@code eidlogin.Handler}, TS {@code createEidLogin} /
 * {@code handleRequest}). The browser side is the TS SDK's {@code <eid-login-button>}; the JSON shapes, cookie and status
 * codes are the same as Go / TS (conformance corpus {@code eidlogin/1}).
 *
 * <pre>
 *   POST {base}/start   {"mode":"qr"} | {"mode":"push","idCode":"УБ12345678"} → {mode, vc, qr?, expiresIn}
 *   GET  {base}/start?mode=web2app                     → 302 → the eID app (Web2App link)
 *   GET  {base}/status                                 → PENDING (+ a fresh QR) | WAIT_CALLBACK | OK | FAILED | EXPIRED
 *   GET  {base}/callback?sessionId&amp;userChallengeVerifier → Web2App return: verified, then 303
 * </pre>
 *
 * The eID server normalises the Web2App callback path to {@code /auth/eid/callback}, so {base} = {@code /auth/eid}.
 * Mount {@link #handle} there with an adapter ({@link EidLoginHttpHandler} for the JDK server, README for Servlet /
 * Spring). The state (session token / secret, rpChallenge, ACSP) stays on the server ({@link EidLoginStore}); the
 * browser holds only the HttpOnly cookie {@code <sessionId>.<binding>} —     * Routes by the last path segment (start | status | callback); anything else 404 {"error":"not_found"}. Store /
     * onSuccess failures never leak internals: 500 {"error":"internal"} on start / status, 303 to the failure redirect
     * with {@code eid_error=internal} on the callback (an RP-API 401 / 403 → 502 eid_unavailable).
     *
     * <p>Blocking: a status call holds its thread for up to {@link Builder#poll} (one at a time per session — a
     * concurrent one answers PENDING at once), a push start for at least the push floor. Run it on virtual threads (Java
     * 21+) or a bounded pool sized for your concurrent sign-ins; never on a single dispatcher thread./ callback answer only the browser that
 * started the sign-in (login CSRF, relay). The citizen reaches {@link Builder#onSuccess} only after the response
 * validator (chain + ACSP_V2 + flowType + the Web2App userChallengeVerifier) and the revocation check.
 *
 * <p>A push (by ID number) never reveals whether the number is registered: when eID refuses the number, a decoy session
 * answers exactly like a real one (PENDING until it expires), and every push answer takes at least the push floor
 * (default 1 s). Thread-safe; share one instance.
 */
public final class EidLogin {
    /** The Web2App return path the eID server normalises to. */
    public static final String CALLBACK_PATH = "/auth/eid/callback";
    /** The default sign-in lifetime. */
    public static final Duration DEFAULT_TTL = Duration.ofMinutes(2);
    /** The default status long-poll per call. */
    public static final Duration DEFAULT_POLL = Duration.ofSeconds(1);
    /** The default push answer floor. */
    public static final Duration DEFAULT_PUSH_FLOOR = Duration.ofSeconds(1);

    /** The default login cookie name when the cookie is Secure, has no Domain and Path is "/" (rp-conformance/2). */
    public static final String HOST_COOKIE_NAME = "__Host-eid_login";
    /** The default login cookie name otherwise (insecure dev cookie, a Domain, or another Path). */
    public static final String PLAIN_COOKIE_NAME = "eid_login";

    static final int MAX_START_BODY = 4 << 10;
    static final int LIMITER_MAX_KEYS = 10_000;
    private static final Duration AUTH_TTL_REFRESH = Duration.ofMinutes(10);
    private static final Duration AUTH_TTL_RETRY = Duration.ofMinutes(1);
    /** The discovery fetch deadline for the push lifetime (Go authTTL: 2 s). */
    static final Duration AUTH_TTL_FETCH_TIMEOUT = Duration.ofSeconds(2);

    private static final Pattern ID_RE = Pattern.compile("^(\\p{L}{2}[0-9]{8}|[0-9]{8,14}|PNOMN-[0-9]{8,14})$");
    private static final Pattern UUID_RE = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern BINDING_RE = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern CIVIL_RE = Pattern.compile("^PNOMN-([0-9]+)$");
    private static final SecureRandom RANDOM = new SecureRandom();

    /** Go {@code Mode}. */
    public static final String MODE_QR = "qr";
    public static final String MODE_PUSH = "push";
    public static final String MODE_WEB2APP = "web2app";

    private final EidClient client;
    private final SuccessHandler onSuccess;
    private final String callbackUrl;
    private final String successRedirect;
    private final String failureRedirect;
    private final CertificateLevel certificateLevel;
    private final Duration ttl;
    private final Duration poll;
    private final EidLoginStore store;
    private final String cookieName;
    private final String cookiePath;
    private final String cookieDomain;
    private final boolean secureCookie;
    private final Map<String, Predicate<String>> limits;
    private final Predicate<String> rateLimitHook;
    private final Function<EidLoginRequest, String> clientIp;
    private final System.Logger log;
    private final boolean decoyOn;
    private final Duration floor;
    private final RevocationChecker revocation;
    private final RevocationMode revocationMode;
    private final Consumer<EidLoginEvent> onEvent;
    private final byte[] auditKey;
    private final List<Interaction> interactions;
    private final Clock clock;
    private final Sleeper sleeper;
    private final Object ttlLock = new Object();
    private Duration caTtl = Duration.ZERO;
    private Instant caTtlNext = Instant.MIN;
    private boolean ttlRefreshing;
    /** Session ids with a status call in progress (per-session single flight). */
    private final java.util.Set<String> polling = java.util.concurrent.ConcurrentHashMap.newKeySet();
    private final java.util.concurrent.atomic.AtomicBoolean warnedNoIp = new java.util.concurrent.atomic.AtomicBoolean();

    /** onSuccess: create YOUR session here (a NEW one — session fixation) and return its Set-Cookie in the headers. */
    @FunctionalInterface
    public interface SuccessHandler {
        /**
         * @return null = no redirect, no data
         * @throws Exception → 500 (status) / the failure redirect (callback)
         */
        EidLoginSuccess onSuccess(EidLoginIdentity identity, EidLoginRequest request) throws Exception;
    }

    /** The wait used for the push floor and the decoy poll (tests replace it). */
    @FunctionalInterface
    interface Sleeper {
        void sleep(Duration d) throws InterruptedException;
    }

    /**
     * One rate rule (Go {@code RateRule}, TS {@code EidLoginRateRule}): {@code func} when given (Redis …); else a memory
     * sliding window of {@code max} per key per {@code window}; max ≤ 0 and no func = unlimited. {@code maxKeys} — the
     * memory window's table size (≤ 0 = 10 000): when full, NEW keys are counted in one shared overflow bucket (same max
     * and window); existing counters are never evicted (Go {@code RateRule.MaxKeys}).
     */
    public record RateRule(int max, Duration window, Predicate<String> func, int maxKeys) {
        /** The 0.2.0 constructor (default table size). */
        public RateRule(int max, Duration window, Predicate<String> func) {
            this(max, window, func, 0);
        }

        public static RateRule of(int max, Duration window) {
            return new RateRule(max, window, null);
        }

        /** A memory window with its own table size ({@code maxKeys} ≤ 0 = 10 000). */
        public static RateRule of(int max, Duration window, int maxKeys) {
            return new RateRule(max, window, null, maxKeys);
        }

        public static RateRule func(Predicate<String> f) {
            return new RateRule(0, null, Objects.requireNonNull(f, "func"));
        }

        public static RateRule unlimited() {
            return new RateRule(0, null, null);
        }
    }

    /** The default limits (new map): start — 20 per 60 s per client IP; push — 3 per 60 s per normalised ID (keyed by its pushKey). */
    public static Map<String, RateRule> defaultRateLimits() {
        Map<String, RateRule> m = new LinkedHashMap<>();
        m.put("start", RateRule.of(20, Duration.ofMinutes(1)));
        m.put("push", RateRule.of(3, Duration.ofMinutes(1)));
        return m;
    }

    private EidLogin(Builder b) {
        client = Objects.requireNonNull(b.client, "eidlogin: client шаардлагатай");
        onSuccess = Objects.requireNonNull(b.onSuccess, "eidlogin: onSuccess шаардлагатай");
        callbackUrl = b.callbackUrl == null ? "" : b.callbackUrl;
        if (!callbackUrl.isEmpty()) {
            URI u;
            try {
                u = new URI(callbackUrl);
            } catch (URISyntaxException e) {
                u = null;
            }
            if (u == null || !"https".equals(u.getScheme()) || u.getHost() == null || u.getHost().isEmpty() || !CALLBACK_PATH.equals(u.getPath())) {
                throw new IllegalArgumentException("eidlogin: callbackUrl нь https://<таны host>" + CALLBACK_PATH + " байх ёстой");
            }
        }
        successRedirect = b.successRedirect == null || b.successRedirect.isEmpty() ? "/" : b.successRedirect;
        failureRedirect = b.failureRedirect == null || b.failureRedirect.isEmpty() ? "/" : b.failureRedirect;
        try {
            new URI(failureRedirect);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("eidlogin: failureRedirect: " + e.getMessage());
        }
        certificateLevel = b.certificateLevel;
        ttl = positive(b.ttl, DEFAULT_TTL);
        poll = positive(b.poll, DEFAULT_POLL);
        clock = b.clock != null ? b.clock : Clock.systemUTC();
        store = b.store != null ? b.store : EidLoginStore.memory(EidLoginStore.MEMORY_MAX, clock);
        cookiePath = b.cookiePath == null || b.cookiePath.isEmpty() ? "/" : b.cookiePath;
        cookieDomain = b.cookieDomain == null ? "" : b.cookieDomain;
        secureCookie = !b.insecureCookie;
        // rp-conformance/2 (Go defaultCookieName): the "__Host-" prefix only where browsers accept it (Secure, no Domain,
        // Path=/) — a cookie planted from a sibling host or another path can then never carry this name.
        cookieName = b.cookieName != null && !b.cookieName.isEmpty() ? b.cookieName
            : secureCookie && cookieDomain.isEmpty() && cookiePath.equals("/") ? HOST_COOKIE_NAME : PLAIN_COOKIE_NAME;
        limits = buildLimits(b.rateLimits, clock);
        rateLimitHook = b.rateLimit;
        clientIp = b.clientIp;
        log = b.logger != null ? b.logger : System.getLogger("mn.eidmongolia.eid.login");
        decoyOn = !b.disableDecoy;
        floor = b.disablePushFloor ? Duration.ZERO : positive(b.pushFloor, DEFAULT_PUSH_FLOOR);
        if (b.disableRevocation) {
            revocation = null;
            revocationMode = null;
        } else {
            revocation = b.revocation != null ? b.revocation : OcspRevocationChecker.create();
            revocationMode = b.revocationMode != null ? b.revocationMode : RevocationMode.SOFT_FAIL;
        }
        onEvent = b.onEvent;
        if (b.auditKey != null && b.auditKey.length > 0) {
            auditKey = b.auditKey.clone();
        } else {
            auditKey = new byte[32];
            RANDOM.nextBytes(auditKey);
        }
        sleeper = b.sleeper != null ? b.sleeper : d -> Thread.sleep(d.toMillis(), d.toNanosPart() % 1_000_000);
        String text = b.displayText == null || b.displayText.isEmpty() ? client.rpName() + "-д нэвтрэх" : b.displayText;
        interactions = List.of(Interaction.displayTextAndPin(truncateCodePoints(text, 60)));
    }

    private static Duration positive(Duration d, Duration def) {
        return d == null || d.isZero() || d.isNegative() ? def : d;
    }

    private static String truncateCodePoints(String s, int n) {
        return s.codePointCount(0, s.length()) <= n ? s : s.substring(0, s.offsetByCodePoints(0, n));
    }

    public static Builder builder(EidClient client) {
        return new Builder(client);
    }

    // ── rate limits (Go buildLimits / windowLimiter) ──

    private static Map<String, Predicate<String>> buildLimits(Map<String, RateRule> user, Clock clock) {
        Map<String, RateRule> merged = defaultRateLimits();
        if (user != null) {
            for (Map.Entry<String, RateRule> e : user.entrySet()) {
                if (!merged.containsKey(e.getKey())) {
                    throw new IllegalArgumentException("eidlogin: rateLimits[\"" + e.getKey() + "\"] — зөвхөн start | push");
                }
                merged.put(e.getKey(), e.getValue() == null ? RateRule.unlimited() : e.getValue());
            }
        }
        Map<String, Predicate<String>> out = new LinkedHashMap<>();
        for (Map.Entry<String, RateRule> e : merged.entrySet()) {
            RateRule r = e.getValue();
            if (r.func() != null) {
                out.put(e.getKey(), r.func());
            } else if (r.max() > 0) {
                if (r.window() == null || r.window().isZero() || r.window().isNegative()) {
                    throw new IllegalArgumentException("eidlogin: rateLimits[\"" + e.getKey() + "\"].window > 0 байх ёстой");
                }
                out.put(e.getKey(), windowLimiter(r.max(), r.window(), r.maxKeys() > 0 ? r.maxKeys() : LIMITER_MAX_KEYS, clock));
            }
        }
        return out;
    }

    /** The shared bucket new keys fall into while the limiter table is full (never a valid kind:value key). */
    static final String OVERFLOW_KEY = "\0overflow";

    /**
     * A memory sliding window per key, at most maxKeys keys. When full it drops keys whose window passed; if still full,
     * a NEW key is counted in one shared overflow bucket (same limit and window) instead of every new key being refused —
     * existing counters are never cleared or evicted, so flooding the table cannot reset a victim's push counter (Go
     * {@code windowLimiter} v0.32.0 does the same).
     */
    static Predicate<String> windowLimiter(int limit, Duration window, int maxKeys, Clock clock) {
        Map<String, List<Instant>> hits = new LinkedHashMap<>();
        return k -> {
            synchronized (hits) {
                String key = k;
                Instant now = clock.instant();
                if (!hits.containsKey(key) && hits.size() >= maxKeys) {
                    hits.values().removeIf(ts -> ts.isEmpty() || Duration.between(ts.get(ts.size() - 1), now).compareTo(window) >= 0);
                    // The overflow bucket itself may be one entry beyond maxKeys.
                    if (hits.size() >= maxKeys) key = OVERFLOW_KEY;
                }
                List<Instant> h = new ArrayList<>();
                for (Instant t : hits.getOrDefault(key, List.of())) if (Duration.between(t, now).compareTo(window) < 0) h.add(t);
                if (h.size() >= limit) {
                    hits.put(key, h);
                    return false;
                }
                h.add(now);
                hits.put(key, h);
                return true;
            }
        };
    }

    private boolean allow(String kind, String value) {
        String key = kind + ":" + value;
        Predicate<String> f = limits.get(kind);
        if (f != null && !f.test(key)) return false;
        return rateLimitHook == null || rateLimitHook.test(key);
    }

    // ── client IP (Go ForwardedClientIP / TS forwardedClientIp) ──

    /**
     * The client IP behind {@code hops} TRUSTED reverse proxies (Go {@code ForwardedClientIP}): the hops-th value from the
     * RIGHT of X-Forwarded-For (nginx alone = 1), X-Real-IP without XFF; "" when XFF has fewer hops (a forged header
     * cannot bypass the limit). Without a proxy never use it — the client sends these headers itself.
     *
     * @throws IllegalArgumentException hops &lt; 1
     */
    public static Function<EidLoginRequest, String> forwardedClientIp(int hops) {
        if (hops < 1) throw new IllegalArgumentException("eidlogin: forwardedClientIp hops >= 1 байх ёстой");
        return r -> {
            List<String> xff = new ArrayList<>();
            List<String> vals = r.headers().get("X-Forwarded-For");
            if (vals != null) {
                for (String v : vals) {
                    for (String p : v.split(",")) {
                        p = p.trim();
                        if (!p.isEmpty()) xff.add(p);
                    }
                }
            }
            if (!xff.isEmpty()) return hops > xff.size() ? "" : xff.get(xff.size() - hops);
            return r.header("X-Real-IP").trim();
        };
    }

    /** The {@code start:<value>} key of a client whose IP could not be derived (one shared, fail-closed bucket). */
    static final String UNKNOWN_IP = "unknown";

    /**
     * The value of the {@code start:<value>} limit key. {@link Builder#clientIp} set: its answer, and an EMPTY answer (a
     * proxy chain shorter than configured, no socket address) is the shared {@value #UNKNOWN_IP} bucket — never "no
     * limit". Not set: the adapter's {@link EidLoginRequest#ip()}; when the adapter gave none either, null = no per-IP
     * limit (warned once). IPv6 clients are keyed by their /64 prefix (one subscriber usually holds a whole /64).
     */
    private String startKey(EidLoginRequest req) {
        String ip;
        if (clientIp != null) {
            ip = clientIp.apply(req);
            if (ip == null || ip.isBlank()) return UNKNOWN_IP;
        } else {
            ip = req.ip();
            if (ip == null || ip.isEmpty()) {
                if (warnedNoIp.compareAndSet(false, true)) {
                    log.log(System.Logger.Level.WARNING, "eidlogin: client IP алга (Builder.clientIp ч, adapter-ийн ip ч үгүй) — start:<ip> "
                        + "хязгаар ажиллахгүй; EidLoginHttpHandler.ClientIp.direct() / trustedProxies(n) эсвэл clientIp(...) өг");
                }
                return null;
            }
        }
        return ipKey(ip.trim());
    }

    /** An IPv6 literal → its /64 prefix ({@code 2001:db8:1:2::/64}); anything else unchanged. Never a DNS lookup. */
    static String ipKey(String ip) {
        if (ip.indexOf(':') < 0) return ip;
        String lit = ip;
        if (lit.startsWith("[") && lit.endsWith("]")) lit = lit.substring(1, lit.length() - 1);
        int zone = lit.indexOf('%');
        if (zone >= 0) lit = lit.substring(0, zone);
        if (lit.isEmpty() || !lit.chars().allMatch(c -> c == ':' || c == '.' || Character.digit(c, 16) >= 0)) return ip;
        byte[] a;
        try {
            // In brackets the JDK parses an IPv6 literal only and never asks the resolver; IPv4-mapped comes back as IPv4.
            a = java.net.InetAddress.getByName("[" + lit + "]").getAddress();
        } catch (java.net.UnknownHostException | SecurityException e) {
            return ip;
        }
        if (a.length == 4) return (a[0] & 0xff) + "." + (a[1] & 0xff) + "." + (a[2] & 0xff) + "." + (a[3] & 0xff);
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < 8; i += 2) b.append(Integer.toHexString(((a[i] & 0xff) << 8) | (a[i + 1] & 0xff))).append(':');
        return b.append(":/64").toString();
    }

    // ── HTTP helpers ──

    private static final class Out {
        final Map<String, List<String>> headers = new LinkedHashMap<>();

        Out set(String k, String v) {
            List<String> l = new ArrayList<>();
            l.add(v);
            headers.put(k, l);
            return this;
        }

        Out add(String k, String v) {
            headers.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
            return this;
        }

        Out merge(Map<String, List<String>> extra) {
            if (extra == null) return this;
            for (Map.Entry<String, List<String>> e : extra.entrySet()) {
                String key = e.getKey();
                for (String k : headers.keySet()) if (k.equalsIgnoreCase(key)) key = k;
                if (key.equalsIgnoreCase("Set-Cookie")) {
                    for (String v : e.getValue()) add(key, v);
                } else {
                    headers.put(key, new ArrayList<>(e.getValue()));
                }
            }
            return this;
        }

        EidLoginResponse json(int status, Object body) {
            set("Content-Type", "application/json; charset=utf-8");
            set("Cache-Control", "no-store");
            return done(status, LoginJson.stringify(body));
        }

        EidLoginResponse redirect(int status, String to) {
            set("Location", to);
            set("Cache-Control", "no-store");
            set("Referrer-Policy", "no-referrer");
            return done(status, "");
        }

        EidLoginResponse done(int status, String body) {
            Map<String, List<String>> h = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> e : headers.entrySet()) h.put(e.getKey(), List.copyOf(e.getValue()));
            return new EidLoginResponse(status, java.util.Collections.unmodifiableMap(h), body);
        }
    }

    private static EidLoginResponse error(int status, String code) {
        return new Out().json(status, Map.of("error", code));
    }

    /** Go http.SetCookie order: Path, Domain, Max-Age, HttpOnly, Secure, SameSite. */
    private String cookie(String value, int maxAge) {
        StringBuilder b = new StringBuilder(cookieName).append('=').append(value).append("; Path=").append(cookiePath);
        if (!cookieDomain.isEmpty()) b.append("; Domain=").append(cookieDomain);
        b.append("; Max-Age=").append(Math.max(0, maxAge)).append("; HttpOnly");
        if (secureCookie) b.append("; Secure");
        return b.append("; SameSite=Lax").toString();
    }

    private String clearCookie() {
        return cookie("", 0);
    }

    static String sha256hex(String s) {
        try {
            byte[] d = MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
            return hex(d);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        return s.toString();
    }

    /** Path / query of the request URL (a path, or a full URL). */
    private static String[] pathQuery(String url) {
        String u = url;
        int sch = u.indexOf("://");
        if (sch > 0 && sch < 10) {
            int slash = u.indexOf('/', sch + 3);
            u = slash < 0 ? "/" : u.substring(slash);
        }
        int h = u.indexOf('#');
        if (h >= 0) u = u.substring(0, h);
        int q = u.indexOf('?');
        return q < 0 ? new String[] {u, ""} : new String[] {u.substring(0, q), u.substring(q + 1)};
    }

    /** The first value of a query parameter (Go {@code url.Values.Get}: '+' = space, %XX decoded); "" when absent. */
    static String queryParam(String rawQuery, String name) {
        for (String part : rawQuery.split("[&]")) {
            if (part.isEmpty()) continue;
            int i = part.indexOf('=');
            String k = i < 0 ? part : part.substring(0, i);
            String v = i < 0 ? "" : part.substring(i + 1);
            try {
                if (URLDecoder.decode(k, StandardCharsets.UTF_8).equals(name)) return URLDecoder.decode(v, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                // a malformed pair is skipped (Go drops it)
            }
        }
        return "";
    }

    /** Go {@code url.Values.Encode} after Set(key, value): keys sorted, QueryEscape. */
    static String setQueryParam(String rawQuery, String key, String value) {
        TreeMap<String, List<String>> m = new TreeMap<>();
        for (String part : rawQuery.split("[&]")) {
            if (part.isEmpty()) continue;
            int i = part.indexOf('=');
            try {
                String k = URLDecoder.decode(i < 0 ? part : part.substring(0, i), StandardCharsets.UTF_8);
                String v = i < 0 ? "" : URLDecoder.decode(part.substring(i + 1), StandardCharsets.UTF_8);
                m.computeIfAbsent(k, x -> new ArrayList<>()).add(v);
            } catch (IllegalArgumentException e) {
                // skipped
            }
        }
        m.put(key, List.of(value));
        StringBuilder b = new StringBuilder();
        for (Map.Entry<String, List<String>> e : m.entrySet()) {
            for (String v : e.getValue()) {
                if (b.length() > 0) b.append('&');
                b.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=').append(URLEncoder.encode(v, StandardCharsets.UTF_8));
            }
        }
        return b.toString();
    }

    /** url with key=value set in its query (fragment kept). */
    static String withQuery(String url, String key, String value) {
        String frag = "";
        int h = url.indexOf('#');
        if (h >= 0) {
            frag = url.substring(h);
            url = url.substring(0, h);
        }
        int q = url.indexOf('?');
        String base = q < 0 ? url : url.substring(0, q);
        String query = q < 0 ? "" : url.substring(q + 1);
        return base + "?" + setQueryParam(query, key, value) + frag;
    }

    // ── routing ──

    /**
     * Routes by the last path segment (start | status | callback); anything else 404 {"error":"not_found"}. Store /
     * onSuccess failures never leak internals: 500 {"error":"internal"} (an RP-API 401 / 403 → 502 eid_unavailable).
     */
    public EidLoginResponse handle(EidLoginRequest req) {
        Objects.requireNonNull(req, "req");
        String path = pathQuery(req.url())[0];
        int end = path.length();
        while (end > 0 && path.charAt(end - 1) == '/') end--;
        String seg = path.substring(path.lastIndexOf('/', end - 1) + 1, end);
        try {
            switch (seg) {
                case "start":
                    return start(req);
                case "status":
                    return status(req);
                case "callback":
                    return callback(req);
                default:
                    return error(404, "not_found");
            }
        } catch (EidException.Authentication | EidException.Forbidden e) {
            log.log(System.Logger.Level.ERROR, "eidlogin: RP-API эрх: " + e.getMessage());
            return error(502, "eid_unavailable");
        } catch (RuntimeException e) {
            log.log(System.Logger.Level.ERROR, "eidlogin: дотоод алдаа: " + e.getClass().getSimpleName());
            return error(500, "internal");
        }
    }

    // ── start ──

    private static final class StartBody {
        String mode = "";
        String idCode = "";
        String lang = "";
    }

    /** Go {@code strings.ToUpper(strings.Join(strings.Fields(s), ""))}: Unicode white space removed, per-rune upper case. */
    static String normaliseId(String s) {
        StringBuilder b = new StringBuilder();
        s.codePoints().forEach(c -> {
            if (!isGoSpace(c)) b.appendCodePoint(Character.toUpperCase(c));
        });
        return b.toString();
    }

    /** Go {@code unicode.IsSpace}. */
    private static boolean isGoSpace(int c) {
        if (c <= 0xff) return c == ' ' || (c >= '\t' && c <= '\r') || c == 0x85 || c == 0xa0;
        return Character.isSpaceChar(c);
    }

    private EidLoginResponse start(EidLoginRequest req) {
        // CSRF: no session / push from a cross-site request. POST is JSON (not a simple request → CORS preflight).
        String site = req.header("Sec-Fetch-Site");
        if (!site.isEmpty() && !site.equals("same-origin") && !site.equals("same-site") && !site.equals("none")) {
            return error(403, "cross_site");
        }
        StartBody b = new StartBody();
        String method = req.lowerMethod();
        String[] pq = pathQuery(req.url());
        if (method.equals("GET")) {
            if (!MODE_WEB2APP.equals(queryParam(pq[1], "mode"))) return error(405, "method_not_allowed");
            b.mode = MODE_WEB2APP;
            b.lang = queryParam(pq[1], "lang");
        } else if (method.equals("POST")) {
            String ct = req.header("Content-Type");
            int semi = ct.indexOf(';');
            if (!(semi < 0 ? ct : ct.substring(0, semi)).trim().toLowerCase(Locale.ROOT).equals("application/json")) {
                return error(415, "json_required");
            }
            if (!readStartBody(req.rawBody(), b)) return error(400, "invalid_body");
        } else {
            return error(405, "method_not_allowed");
        }
        String mode = b.mode;
        if (!mode.equals(MODE_QR) && !mode.equals(MODE_PUSH) && !mode.equals(MODE_WEB2APP)) return error(400, "invalid_mode");
        if (mode.equals(MODE_WEB2APP) && callbackUrl.isEmpty()) return error(400, "web2app_not_configured");
        String idCode = normaliseId(b.idCode);
        if (mode.equals(MODE_PUSH) && !ID_RE.matcher(idCode).matches()) return error(400, "invalid_id");

        String ip = startKey(req);
        if (ip != null && !allow("start", ip)) return limited(mode, idCode);
        // rp-conformance/2: the push key is the audit HMAC (pushKey), never the ID number — no PII reaches the limiter or a
        // user hook (Go Start v0.32.0).
        if (mode.equals(MODE_PUSH) && !allow("push", pushKey(idCode))) return limited(mode, idCode);

        String lang = "en".equals(b.lang) ? "eng" : "mon";
        Instant began = clock.instant();
        Duration t = ttl;
        if (mode.equals(MODE_PUSH)) {
            // Real and decoy pushes take the same lifetime — from discovery, not the CA's answer (a decoy has none).
            Duration ca = authTtl();
            if (!ca.isZero() && ca.compareTo(t) < 0) t = ca;
        }
        Started s = null;
        RuntimeException err = null;
        boolean decoy = false;
        try {
            s = begin(req, mode, idCode, lang, t);
        } catch (RuntimeException e) {
            err = e;
        }
        if (err != null && mode.equals(MODE_PUSH) && decoyOn && isRefusal(err)) {
            // eID refused the number (unknown / unusable): a different answer would be a «registered?» oracle. Answer
            // with a decoy that looks like an unanswered push; the reason stays in the log and onEvent. Status / code only
            // (the body may echo the number).
            EidException.Http he = (EidException.Http) err;
            log.log(System.Logger.Level.WARNING, "eidlogin: eID push-ийг татгалзсан; decoy session-оор хариулав (status "
                + he.status() + ", code " + he.code() + ")");
            err = null;
            try {
                s = startDecoy(t);
                decoy = true;
            } catch (RuntimeException e) {
                err = e;
            }
        }
        if (mode.equals(MODE_PUSH) && !floor.isZero()) {
            // A decoy is ready in microseconds, a real push after eID's round trip — hold both to the same floor.
            sleep(Duration.between(clock.instant(), began.plus(floor)));
        }
        if (err != null) {
            // eID 5xx / connection / 401-403 — our outage (hiding it behind a decoy would show an endless spinner).
            // Registered and unregistered numbers get the same 502.
            log.log(System.Logger.Level.ERROR, "eidlogin: session эхлүүлж чадсангүй (" + mode + "): " + err.getClass().getSimpleName()
                + (err instanceof EidException ? " " + ((EidException) err).code() : ""));
            if (err instanceof EidException && ((EidException) err).status() == 429) return limited(mode, idCode);
            if (err instanceof EidLoginStore.StoreFullException) {
                return new Out().set("Retry-After", "30").json(503, Map.of("error", "busy"));
            }
            return error(502, "eid_unavailable");
        }
        int expiresIn = (int) s.ttl.getSeconds();
        Out out = new Out().add("Set-Cookie", cookie(s.tx.sessionId() + "." + s.binding, expiresIn));
        if (mode.equals(MODE_PUSH)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("mode", mode);
            meta.put("pushKey", pushKey(idCode));
            meta.put("decoy", decoy);
            event(EidLoginEvent.Kind.PUSH_SENT, s.tx.sessionId(), meta);
        }
        if (mode.equals(MODE_WEB2APP)) {
            // An iOS Universal Link opens the app only in a redirect chain started by the user's tap — a 302, not JS.
            return out.redirect(302, s.appLink);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("mode", mode);
        body.put("vc", s.tx.vc());
        body.put("expiresIn", expiresIn);
        String q = qrLink(s.tx);
        if (!q.isEmpty()) body.put("qr", q);
        return out.json(200, body);
    }

    /** Go {@code json.Decoder.Decode} into startBody: an object (or null) whose mode / idCode / lang are strings. */
    private static boolean readStartBody(byte[] raw, StartBody b) {
        if (raw.length > MAX_START_BODY) return false;
        Object v;
        try {
            v = LoginJson.parse(raw);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if (v == LoginJson.NULL) return true;
        if (!(v instanceof Map)) return false;
        Map<?, ?> m = (Map<?, ?>) v;
        String[] keys = {"mode", "idCode", "lang"};
        String[] out = new String[3];
        for (int i = 0; i < 3; i++) {
            Object x = m.get(keys[i]);
            if (x == null || x == LoginJson.NULL) {
                out[i] = "";
            } else if (x instanceof String) {
                out[i] = (String) x;
            } else {
                return false;
            }
        }
        b.mode = out[0];
        b.idCode = out[1];
        b.lang = out[2];
        return true;
    }

    private EidLoginResponse limited(String mode, String idCode) {
        if (mode.equals(MODE_PUSH)) {
            Map<String, Object> meta = new LinkedHashMap<>();
            meta.put("mode", mode);
            meta.put("pushKey", pushKey(idCode));
            event(EidLoginEvent.Kind.PUSH_LIMITED, "", meta);
        }
        return new Out().set("Retry-After", "60").json(429, Map.of("error", "rate_limited"));
    }

    private void sleep(Duration d) {
        if (d.isZero() || d.isNegative()) return;
        try {
            sleeper.sleep(d);
        } catch (InterruptedException e) {
            // The request was cancelled: stop waiting (Go sleepCtx), keep the flag.
            Thread.currentThread().interrupt();
        }
    }

    /**
     * The CA's authentication session lifetime (discovery sessionTtl.auth, cached; Go {@code authTTL}). The fetch is
     * bounded to {@link #AUTH_TTL_FETCH_TIMEOUT} (Go: 2 s) and runs OUTSIDE {@code ttlLock}: one caller refreshes, the
     * others answer with the cached value meanwhile (single flight) — a slow discovery never queues every push behind it.
     */
    private Duration authTtl() {
        Instant now = clock.instant();
        synchronized (ttlLock) {
            if (!now.isAfter(caTtlNext) || ttlRefreshing) return caTtl;
            ttlRefreshing = true;
            caTtlNext = now.plus(AUTH_TTL_RETRY);
        }
        Duration fetched = null;
        try {
            fetched = client.auth().sessionTtl(AUTH_TTL_FETCH_TIMEOUT).auth();
        } catch (EidException e) {
            log.log(System.Logger.Level.WARNING, "eidlogin: discovery sessionTtl: " + e.getClass().getSimpleName());
        } finally {
            synchronized (ttlLock) {
                ttlRefreshing = false;
                if (fetched != null) {
                    if (fetched.compareTo(Duration.ZERO) > 0) caTtl = fetched;
                    caTtlNext = now.plus(AUTH_TTL_REFRESH); // ZERO: an older CA — observeAuthTtl
                }
            }
        }
        synchronized (ttlLock) {
            return caTtl;
        }
    }

    /** An older CA without sessionTtl: the lifetime observed from a real push (Go {@code observeAuthTTL}). */
    private void observeAuthTtl(Instant sent, Instant expiresAt) {
        if (expiresAt == null) return;
        long ms = Duration.between(sent, expiresAt).toMillis();
        long secs = Math.round(ms / 1000.0);
        if (secs <= 0) return;
        synchronized (ttlLock) {
            if (caTtl.isZero()) caTtl = Duration.ofSeconds(secs);
        }
    }

    private static final class Started {
        EidLoginTx tx;
        String binding;
        String appLink = "";
        Duration ttl;
    }

    /** Go {@code begin}: start the eID session and store the state. */
    private Started begin(EidLoginRequest req, String mode, String idCode, String lang, Duration t) {
        Instant sent = clock.instant();
        AuthOptions.Builder o = AuthOptions.builder().certificateLevel(certificateLevel);
        String sid;
        String vc;
        mn.eidmongolia.eid.AcspContext acsp;
        EidLoginTx.Link link = null;
        String appLink = "";
        if (mode.equals(MODE_PUSH)) {
            NotificationSession s = client.auth().notificationByEtsi(idCode, interactions, o.build());
            sid = s.sessionId();
            vc = s.vc();
            acsp = s.acsp();
            observeAuthTtl(sent, s.expiresAt());
        } else {
            if (mode.equals(MODE_WEB2APP)) o.callbackUrl(withReturnHint(callbackUrl, req.header("User-Agent")));
            DeviceLinkSession s = client.auth().deviceLinkAnonymous(interactions, o.build());
            if (empty(s.deviceLinkBase()) || empty(s.sessionToken()) || empty(s.sessionSecret()) || s.acsp() == null) {
                throw new IllegalStateException("eID хариунд device link талбар дутуу");
            }
            sid = s.sessionId();
            vc = s.vc();
            acsp = s.acsp();
            if (s.expiresAt() != null) {
                Duration left = Duration.ofSeconds(Duration.between(clock.instant(), s.expiresAt()).getSeconds());
                if (left.compareTo(t) < 0) t = left;
            }
            link = new EidLoginTx.Link(s.deviceLinkBase(), s.sessionToken(), s.sessionSecret(), s.receivedAt(), lang);
            if (mode.equals(MODE_WEB2APP)) {
                appLink = DeviceLink.build(s.linkInput(DeviceLinkType.WEB2APP, lang).now(clock.instant()).build());
            }
        }
        if (sid == null || !UUID_RE.matcher(sid).matches()) throw new IllegalStateException("eID sessionID хэлбэр буруу");
        if (t.compareTo(Duration.ofSeconds(1)) < 0) throw new IllegalStateException("eID session-ий хугацаа дууссан (expiresAt)");
        Started st = save(new EidLoginTx(sid, "", mode, null, vc, acsp, link, false), t);
        st.appLink = appLink;
        return st;
    }

    private static boolean empty(String s) {
        return s == null || s.isEmpty();
    }

    /** Go {@code save}: a fresh 32-byte binding; the tx stored for t. */
    private Started save(EidLoginTx tx, Duration t) {
        byte[] raw = new byte[32];
        RANDOM.nextBytes(raw);
        String binding = Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
        EidLoginTx full = new EidLoginTx(tx.sessionId(), sha256hex(binding), tx.mode(), clock.instant().plus(t), tx.vc(), tx.acsp(),
            tx.link(), tx.decoy());
        store.set(full, t);
        Started s = new Started();
        s.tx = full;
        s.binding = binding;
        s.ttl = t;
        return s;
    }

    /** Go {@code startDecoy}: a random UUID v4, a 5-digit vc like the CA's (%05d), the real push's lifetime. */
    private Started startDecoy(Duration t) {
        byte[] id = new byte[16];
        RANDOM.nextBytes(id);
        id[6] = (byte) (id[6] & 0x0f | 0x40);
        id[8] = (byte) (id[8] & 0x3f | 0x80);
        String h = hex(id);
        String sid = h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20);
        String vc = String.format(Locale.ROOT, "%05d", RANDOM.nextInt(100000));
        return save(new EidLoginTx(sid, "", MODE_PUSH, null, vc, null, null, true), t);
    }

    /**
     * eID's OWN (JSON body) 4xx: the number was refused (unknown / unusable, request parameter). A non-JSON 4xx is a
     * proxy's in front of eID (an outage); 401 / 403 (the RP's secret / permission) and 429 do not depend on the number —
     * no decoy, hiding them would hide an outage (Go {@code isRefusal}).
     */
    static boolean isRefusal(RuntimeException err) {
        if (!(err instanceof EidException.Http)) return false;
        EidException.Http e = (EidException.Http) err;
        int s = e.status();
        if (s < 400 || s >= 500 || s == 401 || s == 403 || s == 429) return false;
        try {
            LoginJson.parse(e.body().strip().getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IllegalArgumentException x) {
            return false;
        }
    }

    private void event(EidLoginEvent.Kind kind, String sessionId, Map<String, Object> meta) {
        if (onEvent == null) return;
        onEvent.accept(new EidLoginEvent(kind, sessionId == null ? "" : sessionId, java.util.Collections.unmodifiableMap(meta)));
    }

    /** The audit name of an ID number: HMAC-SHA256(auditKey, "eid-push-audit:" + id)[:16], hex (Go {@code pushKey}). */
    String pushKey(String idCode) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(auditKey, "HmacSHA256"));
            byte[] d = mac.doFinal(("eid-push-audit:" + idCode).getBytes(StandardCharsets.UTF_8));
            return hex(java.util.Arrays.copyOf(d, 16));
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private String qrLink(EidLoginTx tx) {
        if (!MODE_QR.equals(tx.mode()) || tx.link() == null || tx.acsp() == null) return "";
        EidLoginTx.Link l = tx.link();
        try {
            return DeviceLink.build(DeviceLinkInput.builder().deviceLinkBase(l.base()).deviceLinkType(DeviceLinkType.QR).sessionToken(l.token())
                .sessionSecret(l.secret()).sessionType(DeviceLinkSessionType.AUTH).lang(l.lang()).receivedAt(l.receivedAt()).now(clock.instant())
                .rpChallenge(tx.acsp().rpChallenge()).relyingPartyName(tx.acsp().relyingPartyName()).interactions(tx.acsp().interactions())
                .build());
        } catch (EidException e) {
            log.log(System.Logger.Level.ERROR, "eidlogin: QR холбоос: " + e.getMessage());
            return "";
        }
    }

    // ── status / callback ──

    /** Go {@code loadTx}: cookie → tx (binding matches, in time); null otherwise. */
    private EidLoginTx loadTx(EidLoginRequest req) {
        String c = req.cookie(cookieName);
        int dot = c.indexOf('.');
        if (dot < 0) return null;
        String sid = c.substring(0, dot);
        String binding = c.substring(dot + 1);
        if (!UUID_RE.matcher(sid).matches() || !BINDING_RE.matcher(binding).matches()) return null;
        EidLoginTx tx = store.get(sid);
        if (tx == null) return null;
        if (!MessageDigest.isEqual(tx.bindingHash().getBytes(StandardCharsets.US_ASCII), sha256hex(binding).getBytes(StandardCharsets.US_ASCII))) {
            return null;
        }
        if (!clock.instant().isBefore(tx.expiresAt())) {
            store.delete(sid);
            return null;
        }
        return tx;
    }

    private EidLoginResponse expired() {
        return new Out().add("Set-Cookie", clearCookie()).json(200, Map.of("state", "EXPIRED"));
    }

    private EidLoginResponse status(EidLoginRequest req) {
        if (!req.lowerMethod().equals("GET")) return error(405, "method_not_allowed");
        EidLoginTx tx = loadTx(req);
        if (tx == null) return expired();
        // Per-session single flight: one status call waits on eID at a time; a concurrent one for the same session answers
        // PENDING at once instead of pinning another thread for the poll (the browser polls again).
        if (!polling.add(tx.sessionId())) return pending(tx);
        try {
            return statusOnce(req, tx);
        } finally {
            polling.remove(tx.sessionId());
        }
    }

    /** The PENDING answer (+ a fresh QR). */
    private EidLoginResponse pending(EidLoginTx tx) {
        long ms = Duration.between(clock.instant(), tx.expiresAt()).toMillis();
        int left = (int) Math.floor(ms / 1000.0 + 0.999);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", "PENDING");
        out.put("vc", tx.vc());
        out.put("expiresIn", Math.max(0, left));
        String q = qrLink(tx);
        if (!q.isEmpty()) out.put("qr", q);
        return new Out().json(200, out);
    }

    private EidLoginResponse statusOnce(EidLoginRequest req, EidLoginTx tx) {
        SessionResult res;
        if (tx.decoy()) {
            // Never ask eID (a 404 would turn into EXPIRED and give it away): hold for the poll like a real long-poll.
            sleep(poll);
            res = null; // RUNNING
        } else {
            try {
                res = client.session().poll(tx.sessionId(), poll);
            } catch (EidException.Api e) {
                if (e.status() == 404) {
                    store.delete(tx.sessionId());
                    event(EidLoginEvent.Kind.EXPIRED, tx.sessionId(), meta("mode", tx.mode()));
                    return expired();
                }
                log.log(System.Logger.Level.ERROR, "eidlogin: session poll: " + e.status() + " " + e.code());
                return error(502, "eid_unavailable");
            } catch (EidException e) {
                log.log(System.Logger.Level.ERROR, "eidlogin: session poll: " + e.getClass().getSimpleName());
                return error(502, "eid_unavailable");
            }
        }
        if (res == null || !SessionResult.STATE_COMPLETE.equals(res.state())) return pending(tx);
        String endResult = res.endResult() == null ? "" : res.endResult();
        if (!SessionResult.END_RESULT_OK.equals(endResult)) {
            endEvent(tx, endResult);
            if (MODE_PUSH.equals(tx.mode()) && SessionResult.END_RESULT_TIMEOUT.equals(endResult)) {
                // An unanswered real push ends like a decoy (EXPIRED) — FAILED/TIMEOUT would say «registered».
                store.delete(tx.sessionId());
                return expired();
            }
            return failed(tx, orUnknown(endResult));
        }
        // A session verified via Web2App is finished ONLY by the callback (userChallengeVerifier).
        if (MODE_WEB2APP.equals(tx.mode())) return new Out().json(200, Map.of("state", "WAIT_CALLBACK"));
        FlowType flow = MODE_PUSH.equals(tx.mode()) ? FlowType.NOTIFICATION : FlowType.QR;
        EidLoginSuccess s;
        try {
            s = finish(req, tx, res, flow, "");
        } catch (RuntimeException e) {
            if (!isValidation(e)) throw e;
            log.log(System.Logger.Level.WARNING, "eidlogin: баталгаажуулалт унасан: " + reasonOf(e));
            unverified(tx, e);
            return failed(tx, "VALIDATION");
        }
        if (s == null) return expired();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", "OK");
        if (s.redirect() != null && !s.redirect().isEmpty()) out.put("redirect", s.redirect());
        if (s.data() != null) out.put("data", s.data());
        return new Out().add("Set-Cookie", clearCookie()).merge(s.headers()).json(200, out);
    }

    private EidLoginResponse failed(EidLoginTx tx, String code) {
        store.delete(tx.sessionId());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("state", "FAILED");
        out.put("error", code);
        return new Out().add("Set-Cookie", clearCookie()).json(200, out);
    }

    private EidLoginResponse callback(EidLoginRequest req) {
        if (!req.lowerMethod().equals("GET")) return error(405, "method_not_allowed");
        String q = pathQuery(req.url())[1];
        String sid = queryParam(q, "sessionId");
        String verifier = queryParam(q, "userChallengeVerifier");
        EidLoginTx tx;
        try {
            tx = loadTx(req);
        } catch (RuntimeException e) {
            // A store failure on a browser navigation: the failure page (303 eid_error=internal, Go), not a JSON 500.
            log.log(System.Logger.Level.ERROR, "eidlogin: store: " + e.getClass().getSimpleName());
            return fail("internal", null);
        }
        // The starting browser's cookie is required: a callback opened in another browser (a stolen / forwarded URL) is refused.
        if (tx == null) return fail("expired", null);
        if (!tx.sessionId().equals(sid) || !MODE_WEB2APP.equals(tx.mode()) || verifier.isEmpty()) {
            Map<String, Object> meta = meta("mode", tx.mode());
            meta.put("reason", "unbound");
            event(EidLoginEvent.Kind.FLOW_REFUSED, tx.sessionId(), meta);
            return fail("unbound", null);
        }
        SessionResult res;
        try {
            res = client.session().poll(tx.sessionId(), Duration.ofSeconds(10));
        } catch (EidException e) {
            log.log(System.Logger.Level.ERROR, "eidlogin: session poll: " + e.getClass().getSimpleName());
            return fail("eid_unavailable", null);
        }
        if (!SessionResult.STATE_COMPLETE.equals(res.state())) return fail("not_complete", null);
        String endResult = res.endResult() == null ? "" : res.endResult();
        if (!SessionResult.END_RESULT_OK.equals(endResult)) {
            deleteQuietly(tx);
            endEvent(tx, endResult);
            return fail(orUnknown(endResult), null);
        }
        EidLoginSuccess s;
        try {
            s = finish(req, tx, res, FlowType.WEB2APP, verifier);
        } catch (RuntimeException e) {
            if (!isValidation(e)) {
                log.log(System.Logger.Level.ERROR, "eidlogin: дуусгаж чадсангүй: " + e.getClass().getSimpleName());
                return fail("internal", null);
            }
            log.log(System.Logger.Level.WARNING, "eidlogin: баталгаажуулалт унасан: " + reasonOf(e));
            deleteQuietly(tx);
            unverified(tx, e);
            return fail("VALIDATION", null);
        }
        if (s == null) return fail("expired", null);
        String to = s.redirect() == null || s.redirect().isEmpty() ? successRedirect : s.redirect();
        return new Out().add("Set-Cookie", clearCookie()).merge(s.headers()).redirect(303, to);
    }

    /** store.delete for the callback (Go deleteTx): a store failure is logged, the answer stays the redirect. */
    private void deleteQuietly(EidLoginTx tx) {
        try {
            store.delete(tx.sessionId());
        } catch (RuntimeException e) {
            log.log(System.Logger.Level.ERROR, "eidlogin: store: " + e.getClass().getSimpleName());
        }
    }

    private EidLoginResponse fail(String code, Map<String, List<String>> extra) {
        return new Out().add("Set-Cookie", clearCookie()).merge(extra).redirect(303, withQuery(failureRedirect, "eid_error", code));
    }

    private static Map<String, Object> meta(String k, Object v) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put(k, v);
        return m;
    }

    private static String orUnknown(String s) {
        return s == null || s.isEmpty() ? "UNKNOWN" : s;
    }

    /** Go {@code endEvent}: COMPLETE with endResult ≠ OK. */
    private void endEvent(EidLoginTx tx, String endResult) {
        EidLoginEvent.Kind kind = EidLoginEvent.Kind.FAILED;
        if (endResult.startsWith(SessionResult.END_RESULT_USER_REFUSED)) kind = EidLoginEvent.Kind.REFUSED;
        else if (endResult.equals(SessionResult.END_RESULT_TIMEOUT)) kind = EidLoginEvent.Kind.EXPIRED;
        Map<String, Object> m = meta("mode", tx.mode());
        m.put("endResult", orUnknown(endResult));
        event(kind, tx.sessionId(), m);
    }

    /** The revocation check failed (Go {@code revocationError}). */
    static final class RevocationFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;
        final boolean revoked;

        RevocationFailure(boolean revoked, Throwable cause) {
            super(cause.getMessage(), cause);
            this.revoked = revoked;
        }
    }

    private void unverified(EidLoginTx tx, RuntimeException e) {
        String reason = "validation";
        if (e instanceof RevocationFailure) reason = ((RevocationFailure) e).revoked ? "revoked" : "revocation_unavailable";
        Map<String, Object> m = meta("mode", tx.mode());
        m.put("reason", reason);
        event(EidLoginEvent.Kind.UNVERIFIED, tx.sessionId(), m);
    }

    private static boolean isValidation(RuntimeException e) {
        return e instanceof EidException.Validation || e instanceof EidException.SessionFailed || e instanceof RevocationFailure;
    }

    private static String reasonOf(RuntimeException e) {
        if (e instanceof EidException.Validation) return ((EidException.Validation) e).reason();
        if (e instanceof RevocationFailure) return ((RevocationFailure) e).revoked ? "revoked" : "revocation_unavailable";
        return e.getClass().getSimpleName();
    }

    /** Go {@code finish}: verify COMPLETE/OK and call onSuccess once; null = a concurrent request already finished it. */
    private EidLoginSuccess finish(EidLoginRequest req, EidLoginTx tx, SessionResult res, FlowType flow, String verifier) {
        VerifiedIdentity v = client.validator().validateAuth(res, tx.acsp(),
            ValidateAuthOptions.builder().expectedFlowType(flow).userChallengeVerifier(verifier.isEmpty() ? null : verifier).build());
        RevocationOutcome rev;
        try {
            rev = client.validator().checkRevocationWith(v.certificate(), revocation, revocationMode);
        } catch (EidException.Validation e) {
            throw new RevocationFailure(ValidationReasons.REVOCATION_REVOKED.equals(e.reason()), e);
        } catch (EidException e) {
            // The checker's own failure (a custom checker) — not trusted, but not a 500 either.
            throw new RevocationFailure(false, e);
        }
        if (rev == RevocationOutcome.UNCHECKED) {
            log.log(System.Logger.Level.WARNING, "eidlogin: OCSP хариугүй — цуцлалт шалгалгүй зөвшөөрөв (soft-fail)");
        }
        if (!store.delete(tx.sessionId())) return null;
        String etsi = v.subject().serialNumber();
        Matcher m = CIVIL_RE.matcher(etsi);
        String civil = m.matches() ? m.group(1) : "";
        Person p = res.person();
        Person person = p != null && p.civilId() != null && !p.civilId().isEmpty() && !etsi.isEmpty() && etsi.equals("PNOMN-" + p.civilId()) ? p : null;
        EidLoginIdentity id = new EidLoginIdentity(tx.sessionId(), etsi, civil, v.subject().givenName(), v.subject().surname(),
            v.subject().country(), v.documentNumber(), v.certificateLevel(), v.certificate(), flow, person, rev);
        EidLoginSuccess s;
        try {
            s = onSuccess.onSuccess(id, req);
        } catch (RuntimeException e) {
            throw new IllegalStateException("OnSuccess: " + e.getClass().getSimpleName(), e);
        } catch (Exception e) {
            throw new IllegalStateException("OnSuccess: " + e.getClass().getSimpleName(), e);
        }
        if (s == null) s = new EidLoginSuccess(null, null, null);
        Map<String, Object> meta = meta("mode", tx.mode());
        meta.put("flow", flow.wireName());
        meta.put("revocation", rev.wireName());
        event(EidLoginEvent.Kind.SUCCESS, tx.sessionId(), meta);
        return s;
    }

    // ── Web2App return hint (Go WithReturnHint) ──

    private static final String[][] IOS_BROWSERS = {{"CriOS", "googlechromes"}, {"EdgiOS", "microsoft-edge-https"},
        {"FxiOS", "firefox"}, {"OPT/", "touch-https"}, {"OPiOS|OPR/", "opera-https"}, {"DuckDuckGo", "ddgQuickLink"}};
    private static final String[][] ANDROID_BROWSERS = {{"EdgA/", "com.microsoft.emmx"}, {"Opera Mini", "com.opera.mini.native"},
        {"OPR/", "com.opera.browser"}, {"SamsungBrowser/", "com.sec.android.app.sbrowser"}, {"YaBrowser/", "com.yandex.browser"},
        {"DuckDuckGo/", "com.duckduckgo.mobile.android"}, {"Vivaldi/", "com.vivaldi.browser"}, {"Firefox/", "org.mozilla.firefox"},
        {"Chrome/", "com.android.chrome"}};
    private static final Pattern IOS_RE = Pattern.compile("(?i)iPhone|iPad|iPod");
    private static final Pattern ANDROID_RE = Pattern.compile("(?i)Android");

    /**
     * callbackUrl with the return-browser hint (retScheme on iOS / retPkg on Android) the eID app uses after approval
     * (CA docs/RP_GEREGE_INTEGRATION.md §1.1b); unchanged when the browser is not recognised.
     */
    public static String withReturnHint(String callbackUrl, String userAgent) {
        String ua = userAgent == null ? "" : userAgent;
        String key = "";
        String val = "";
        if (IOS_RE.matcher(ua).find()) {
            key = "retScheme";
            val = pick(IOS_BROWSERS, ua);
        } else if (ANDROID_RE.matcher(ua).find()) {
            key = "retPkg";
            val = pick(ANDROID_BROWSERS, ua);
        }
        if (val.isEmpty()) return callbackUrl;
        return withQuery(callbackUrl, key, val);
    }

    private static String pick(String[][] t, String ua) {
        for (String[] b : t) if (Pattern.compile("(?i)" + b[0]).matcher(ua).find()) return b[1];
        return "";
    }

    /** {@link EidLogin} configuration (Go {@code eidlogin.Config}, TS {@code EidLoginOptions}). */
    public static final class Builder {
        private final EidClient client;
        private SuccessHandler onSuccess;
        private String callbackUrl;
        private String successRedirect;
        private String failureRedirect;
        private String displayText;
        private CertificateLevel certificateLevel;
        private Duration ttl;
        private Duration poll;
        private EidLoginStore store;
        private String cookieName;
        private String cookiePath;
        private String cookieDomain;
        private boolean insecureCookie;
        private Map<String, RateRule> rateLimits;
        private Predicate<String> rateLimit;
        private Function<EidLoginRequest, String> clientIp;
        private System.Logger logger;
        private boolean disableDecoy;
        private Duration pushFloor;
        private boolean disablePushFloor;
        private RevocationChecker revocation;
        private RevocationMode revocationMode;
        private boolean disableRevocation;
        private Consumer<EidLoginEvent> onEvent;
        private byte[] auditKey;
        private Clock clock;
        private Sleeper sleeper;

        private Builder(EidClient client) {
            this.client = client;
        }

        /** REQUIRED: create the RP session here — identify the user by {@link EidLoginIdentity#etsi()}, a NEW session. */
        public Builder onSuccess(SuccessHandler v) {
            onSuccess = v;
            return this;
        }

        /**
         * The Web2App return URL: https, your host (in the RP's callbackHosts), path EXACTLY {@value #CALLBACK_PATH}.
         * Empty = mode web2app answers 400 (QR / push only).
         */
        public Builder callbackUrl(String v) {
            callbackUrl = v;
            return this;
        }

        /** After a successful callback when onSuccess gave no redirect. Default "/". */
        public Builder successRedirect(String v) {
            successRedirect = v;
            return this;
        }

        /** After a failed callback, with ?eid_error=&lt;code&gt;. Default "/". */
        public Builder failureRedirect(String v) {
            failureRedirect = v;
            return this;
        }

        /** The phone's text (≤ 60). Default «&lt;rpName&gt;-д нэвтрэх». */
        public Builder displayText(String v) {
            displayText = v;
            return this;
        }

        public Builder certificateLevel(CertificateLevel v) {
            certificateLevel = v;
            return this;
        }

        /**
         * The sign-in lifetime (default 2 min), never longer than the CA's session: QR / Web2App — min(ttl, CA expiresAt −
         * now); push (real and decoy alike) — min(ttl, discovery sessionTtl.auth).
         */
        public Builder ttl(Duration v) {
            ttl = v;
            return this;
        }

        /**
         * How long one status call waits on eID (default 1 s) — the thread is held for that long. Per session only one
         * status call waits at a time; a concurrent one answers PENDING immediately.
         */
        public Builder poll(Duration v) {
            poll = v;
            return this;
        }

        /** Default {@link EidLoginStore#memory()} (one process). */
        public Builder store(EidLoginStore v) {
            store = v;
            return this;
        }

        /**
         * The login cookie's name, used as given. Default (after 0.2.x): {@value EidLogin#HOST_COOKIE_NAME} when the
         * cookie is Secure, has no Domain and Path is "/", else {@value EidLogin#PLAIN_COOKIE_NAME} (0.2.x always used
         * eid_login — logins in progress during the upgrade restart once). A request carrying the name more than once is
         * treated as carrying no login cookie.
         */
        public Builder cookieName(String v) {
            cookieName = v;
            return this;
        }

        /** Default "/". */
        public Builder cookiePath(String v) {
            cookiePath = v;
            return this;
        }

        public Builder cookieDomain(String v) {
            cookieDomain = v;
            return this;
        }

        /** No Secure attribute — plain-http development ONLY. */
        public Builder insecureCookie(boolean v) {
            insecureCookie = v;
            return this;
        }

        /**
         * Per-kind limits ("start" — key "start:&lt;ip&gt;", "push" — "push:&lt;pushKey&gt;"), MERGED with
         * {@link #defaultRateLimits()}: a given kind replaces its default; {@link RateRule#unlimited()} turns it off.
         * The push key is the audit {@code pushKey} (32 hex, HMAC of the normalised ID under {@link #auditKey}) — never the
         * ID number itself (0.2.x used "push:&lt;id&gt;"). The per-ID push limit still means anyone who knows a citizen's
         * ID number can use up its window and delay that citizen's PUSH sign-in for up to a window (inherent to
         * push-by-ID; QR / Web2App are unaffected). For a limiter shared by several instances set the same
         * {@link #auditKey} on all of them.
         *
         * @throws IllegalArgumentException (build) another kind
         */
        public Builder rateLimits(Map<String, RateRule> v) {
            rateLimits = v;
            return this;
        }

        /**
         * An extra check for every key ("start:&lt;ip&gt;" — IPv6 by its /64, "start:unknown" when the configured client-IP
         * source answers empty; "push:&lt;pushKey&gt;" — never the ID number); false → 429. Added ON TOP of the limits.
         */
        public Builder rateLimit(Predicate<String> v) {
            rateLimit = v;
            return this;
        }

        /**
         * The client IP for "start:&lt;ip&gt;" — e.g. {@link EidLogin#forwardedClientIp}(n) behind n trusted proxies. It
         * OVERRIDES the adapter's {@link EidLoginRequest#ip()}: never set it without a proxy (clients would choose their
         * own key via X-Forwarded-For). An empty answer counts in one shared "start:unknown" bucket; IPv6 is keyed by
         * its /64. null = the adapter's ip; neither → no per-IP limit (a one-time warning is logged).
         */
        public Builder clientIp(Function<EidLoginRequest, String> v) {
            clientIp = v;
            return this;
        }

        /** Internal errors (default System.getLogger("mn.eidmongolia.eid.login")). Never citizen data. */
        public Builder logger(System.Logger v) {
            logger = v;
            return this;
        }

        /**
         * eID refusing a push number answers 502 eid_unavailable instead of a decoy. WARNING: /start then tells anyone
         * whether an ID number is registered with eID. Internal / test environments only.
         */
        public Builder disableDecoy(boolean v) {
            disableDecoy = v;
            return this;
        }

        /** Every push start answer (real, decoy, 502) takes at least this long. Default 1 s. Not 429 / 400. */
        public Builder pushFloor(Duration v) {
            pushFloor = v;
            return this;
        }

        /** No push floor. WARNING: decoys become distinguishable by timing. */
        public Builder disablePushFloor(boolean v) {
            disablePushFloor = v;
            return this;
        }

        /** The citizen-certificate revocation checker (before onSuccess). Default {@link OcspRevocationChecker#create()}. */
        public Builder revocation(RevocationChecker v) {
            revocation = v;
            return this;
        }

        /**
         * No OCSP answer: null = SOFT_FAIL (accepted, logged, identity.revocation = unchecked — the eID portal's
         * EID_OCSP=soft); HARD_FAIL → FAILED "VALIDATION".
         */
        public Builder revocationMode(RevocationMode v) {
            revocationMode = v;
            return this;
        }

        /** No revocation check (identity.revocation = skipped). WARNING: a stolen phone's revoked certificate signs in. */
        public Builder disableRevocation(boolean v) {
            disableRevocation = v;
            return this;
        }

        /** The audit hook — synchronous on the request thread; keep it fast. */
        public Builder onEvent(Consumer<EidLoginEvent> v) {
            onEvent = v;
            return this;
        }

        /** The pushKey HMAC key (≥ 32 bytes recommended). null = random per instance (pushKey only stable in-process). */
        public Builder auditKey(byte[] v) {
            auditKey = v == null ? null : v.clone();
            return this;
        }

        /** Tests: the clock for TTLs, the store, the limiter and the push floor. */
        Builder clock(Clock v) {
            clock = v;
            return this;
        }

        /** Tests: the push-floor / decoy-poll wait. */
        Builder sleeper(Sleeper v) {
            sleeper = v;
            return this;
        }

        /** @throws IllegalArgumentException / NullPointerException on a bad configuration */
        public EidLogin build() {
            return new EidLogin(this);
        }
    }
}
