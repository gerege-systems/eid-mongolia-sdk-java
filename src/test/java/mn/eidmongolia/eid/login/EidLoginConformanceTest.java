package mn.eidmongolia.eid.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import mn.eidmongolia.eid.Credentials;
import mn.eidmongolia.eid.EidClient;
import mn.eidmongolia.eid.EidHttpRequest;
import mn.eidmongolia.eid.EidHttpResponse;
import mn.eidmongolia.eid.EidTransport;
import org.junit.Test;

/**
 * Every scenario of the cross-SDK login corpus {@code conformance/eidlogin/scenarios.json} (eidlogin/2, Go eidlogin
 * conformance_test.go / TS conformance.test.ts) against the framework-neutral {@link EidLogin#handle}, asserting every
 * expected field (status, JSON subset / exact keys, Location, headers, Set-Cookie value and attributes, events,
 * rate-limit keys). Fails when the file is missing, does not hold exactly 34 scenarios, or carries a key this harness
 * does not implement (a newer corpus must not pass silently).
 */
public class EidLoginConformanceTest {
    static final String HOST = "https://rp.conformance.test";

    @SuppressWarnings("unchecked")
    static Map<String, Object> corpus() {
        try (InputStream in = EidLoginConformanceTest.class.getResourceAsStream("/conformance/eidlogin/scenarios.json")) {
            assertNotNull("conformance/eidlogin/scenarios.json алга", in);
            return (Map<String, Object>) LoginJson.parse(in.readAllBytes());
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> obj(Object o) {
        return o == null ? Map.of() : (Map<String, Object>) o;
    }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object o) {
        return o == null ? List.of() : (List<Object>) o;
    }

    static String str(Object o) {
        return o instanceof String ? (String) o : "";
    }

    static int num(Object o) {
        return ((BigDecimal) o).intValueExact();
    }

    /** The fake RP-API: first rule matching method + path (query ignored) or pathPrefix. */
    static final class Upstream implements EidTransport {
        final List<Map<String, Object>> rules = new ArrayList<>();

        @Override
        public EidHttpResponse send(EidHttpRequest r) {
            String path = r.uri().getRawPath();
            for (Map<String, Object> rule : rules) {
                if (!str(rule.get("method")).equals(r.method())) continue;
                boolean match = rule.containsKey("path") ? str(rule.get("path")).equals(path)
                    : path.startsWith(str(rule.get("pathPrefix")));
                if (!match) continue;
                String ct = rule.containsKey("contentType") ? str(rule.get("contentType")) : "application/json";
                String body;
                if (rule.containsKey("bodyText")) {
                    body = str(rule.get("bodyText"));
                } else {
                    Map<String, Object> b = new LinkedHashMap<>(obj(rule.get("body")));
                    if (rule.containsKey("expiresAtInSeconds")) {
                        b.put("expiresAt", Instant.now().plusSeconds(num(rule.get("expiresAtInSeconds"))).truncatedTo(ChronoUnit.SECONDS).toString());
                    }
                    body = LoginJson.stringify(b);
                }
                return new EidHttpResponse(num(rule.get("status")), Map.of("Content-Type", List.of(ct)), body.getBytes(StandardCharsets.UTF_8));
            }
            return new EidHttpResponse(404, Map.of("Content-Type", List.of("application/json")), "{\"error\":\"not found\"}".getBytes(StandardCharsets.UTF_8));
        }
    }

    /** One step's answer as the matchers see it. */
    static final class Got {
        EidLoginResponse res;
        Map<String, Object> json;
        String cookieValue;
        Map<String, Object> cookieAttrs;
    }

    @Test
    public void allScenarios() {
        Map<String, Object> c = corpus();
        assertEquals("eidlogin/2", c.get("version"));
        checkKeys(c);
        List<Object> scenarios = arr(c.get("scenarios"));
        assertEquals("scenarios", 34, scenarios.size());
        List<String> failures = new ArrayList<>();
        for (Object o : scenarios) {
            Map<String, Object> s = obj(o);
            try {
                run(obj(c.get("config")), arr(c.get("upstream")), s);
            } catch (AssertionError | RuntimeException e) {
                failures.add(s.get("name") + ": " + e.getMessage());
            }
        }
        assertEquals(String.join("\n", failures), 0, failures.size());
    }

    static final java.util.Set<String> TOP_KEYS = java.util.Set.of("version", "comment", "config", "upstream", "scenarios");
    static final java.util.Set<String> CONFIG_KEYS = java.util.Set.of("rpName", "rpUUID", "apiSecret", "callbackUrl", "successRedirect",
        "failureRedirect", "ttlSeconds", "pollMs", "pushFloorMs", "cookieName", "wireCookieName", "cookieDomain", "cookiePath", "clientIp",
        "auditKeyHex", "rateLimits", "revocation", "decoy", "recordRateLimitKeys");
    static final java.util.Set<String> RULE_KEYS = java.util.Set.of("method", "path", "pathPrefix", "status", "body", "bodyText", "contentType",
        "expiresAtInSeconds");
    static final java.util.Set<String> SCENARIO_KEYS = java.util.Set.of("name", "comment", "config", "upstream", "steps", "events", "rateLimitKeys");
    static final java.util.Set<String> STEP_KEYS = java.util.Set.of("request", "repeat", "expect", "upstream");
    static final java.util.Set<String> REQUEST_KEYS = java.util.Set.of("method", "path", "headers", "json", "text", "cookieFrom", "cookieHeader", "ip");
    static final java.util.Set<String> EXPECT_KEYS = java.util.Set.of("status", "json", "jsonKeys", "sameKeysAs", "location", "headers", "setCookie",
        "noSetCookie");
    static final java.util.Set<String> SET_COOKIE_KEYS = java.util.Set.of("value", "attributes", "absentAttributes", "cleared");
    static final java.util.Set<String> EVENT_KEYS = java.util.Set.of("kind", "sessionId", "meta");

    static void only(String at, Map<String, Object> m, java.util.Set<String> allowed) {
        for (String k : m.keySet()) assertTrue(at + ": unknown corpus key \"" + k + "\" (harness does not implement it)", allowed.contains(k));
    }

    /** Every member of the corpus must be one this harness implements — a newer corpus must fail, not pass silently. */
    static void checkKeys(Map<String, Object> c) {
        only("top", c, TOP_KEYS);
        only("config", obj(c.get("config")), CONFIG_KEYS);
        for (Object r : arr(c.get("upstream"))) only("upstream", obj(r), RULE_KEYS);
        for (Object o : arr(c.get("scenarios"))) {
            Map<String, Object> s = obj(o);
            String n = str(s.get("name"));
            only(n, s, SCENARIO_KEYS);
            only(n + " config", obj(s.get("config")), CONFIG_KEYS);
            for (Object r : arr(s.get("upstream"))) only(n + " upstream", obj(r), RULE_KEYS);
            for (Object e : arr(s.get("events"))) only(n + " event", obj(e), EVENT_KEYS);
            for (Object so : arr(s.get("steps"))) {
                Map<String, Object> st = obj(so);
                only(n + " step", st, STEP_KEYS);
                for (Object r : arr(st.get("upstream"))) only(n + " step upstream", obj(r), RULE_KEYS);
                Map<String, Object> rq = obj(st.get("request"));
                only(n + " request", rq, REQUEST_KEYS);
                assertTrue(n + ": cookieHeader without cookieFrom", !rq.containsKey("cookieHeader") || rq.containsKey("cookieFrom"));
                Map<String, Object> ex = obj(st.get("expect"));
                only(n + " expect", ex, EXPECT_KEYS);
                only(n + " setCookie", obj(ex.get("setCookie")), SET_COOKIE_KEYS);
            }
        }
    }

    static void run(Map<String, Object> baseCfg, List<Object> baseUp, Map<String, Object> s) {
        Map<String, Object> cfg = new LinkedHashMap<>(baseCfg);
        cfg.putAll(obj(s.get("config")));
        Upstream up = new Upstream();
        for (Object r : arr(s.get("upstream"))) up.rules.add(obj(r));
        for (Object r : baseUp) up.rules.add(obj(r));

        EidClient client = EidClient.builder(new Credentials(str(cfg.get("rpUUID")), str(cfg.get("rpName")), str(cfg.get("apiSecret"))))
            .baseUrl("https://rp-api.conformance.test").transport(up).build();
        List<EidLoginEvent> events = Collections.synchronizedList(new ArrayList<>());
        List<String> keys = Collections.synchronizedList(new ArrayList<>());
        // wireCookieName — the name the browser sees (cookieName "" = the SDK default; README §eidlogin).
        String cookieName = str(cfg.get("wireCookieName")).isEmpty() ? str(cfg.get("cookieName")) : str(cfg.get("wireCookieName"));
        boolean noClientIp = "none".equals(cfg.get("clientIp"));
        EidLogin.Builder lb = EidLogin.builder(client)
            .callbackUrl(str(cfg.get("callbackUrl")))
            .successRedirect(str(cfg.get("successRedirect")))
            .failureRedirect(str(cfg.get("failureRedirect")))
            .ttl(Duration.ofSeconds(num(cfg.get("ttlSeconds"))))
            .poll(Duration.ofMillis(num(cfg.get("pollMs"))))
            .cookieName(str(cfg.get("cookieName")))
            .cookieDomain(str(cfg.get("cookieDomain")))
            .cookiePath(str(cfg.get("cookiePath")))
            .disableDecoy(!Boolean.TRUE.equals(cfg.get("decoy")))
            .onEvent(events::add)
            .onSuccess((id, req) -> EidLoginSuccess.redirect("/dashboard"));
        // A client-IP source returning the request's ip; "none" = no source at all (and no adapter ip either).
        if (!noClientIp) lb.clientIp(EidLoginRequest::ip);
        if (!str(cfg.get("auditKeyHex")).isEmpty()) lb.auditKey(java.util.HexFormat.of().parseHex(str(cfg.get("auditKeyHex"))));
        if (cfg.get("rateLimits") != null) {
            Map<String, EidLogin.RateRule> rl = new LinkedHashMap<>();
            for (Map.Entry<String, Object> e : obj(cfg.get("rateLimits")).entrySet()) {
                Map<String, Object> m = obj(e.getValue());
                assertEquals("rateLimits." + e.getKey() + " keys", new TreeSet<>(List.of("max", "maxKeys", "windowSeconds")),
                    new TreeSet<>(m.keySet()));
                rl.put(e.getKey(), EidLogin.RateRule.of(num(m.get("max")), Duration.ofSeconds(num(m.get("windowSeconds"))), num(m.get("maxKeys"))));
            }
            lb.rateLimits(rl);
        }
        int floor = num(cfg.get("pushFloorMs"));
        if (floor == 0) lb.disablePushFloor(true);
        else lb.pushFloor(Duration.ofMillis(floor));
        if ("disabled".equals(cfg.get("revocation"))) lb.disableRevocation(true);
        if (Boolean.TRUE.equals(cfg.get("recordRateLimitKeys"))) {
            lb.rateLimit(k -> {
                keys.add(k);
                return true;
            });
        }
        EidLogin login = lb.build();

        List<Got> got = new ArrayList<>();
        List<Object> steps = arr(s.get("steps"));
        for (int i = 0; i < steps.size(); i++) {
            Map<String, Object> st = obj(steps.get(i));
            List<Object> stepUp = arr(st.get("upstream"));
            for (int k = stepUp.size() - 1; k >= 0; k--) up.rules.add(0, obj(stepUp.get(k)));
            int repeat = st.containsKey("repeat") ? num(st.get("repeat")) : 1;
            Got g = null;
            for (int n = 0; n < repeat; n++) {
                g = send(login, obj(st.get("request")), got, cookieName, noClientIp);
                List<Got> view = new ArrayList<>(got);
                view.add(g); // $sameAs may name the current step
                check("step " + i + (repeat > 1 ? " #" + n : ""), obj(st.get("expect")), g, view);
            }
            got.add(g);
        }
        if (s.containsKey("events")) {
            List<Object> want = arr(s.get("events"));
            List<EidLoginEvent> ev = new ArrayList<>(events);
            assertEquals("events " + ev, want.size(), ev.size());
            for (int i = 0; i < want.size(); i++) {
                Map<String, Object> w = obj(want.get(i));
                EidLoginEvent e = ev.get(i);
                assertEquals("event " + i + " kind", w.get("kind"), e.kind().wireName());
                if (w.containsKey("sessionId")) {
                    Object ws = w.get("sessionId");
                    match("event " + i + " sessionId", ws == LoginJson.NULL ? "" : ws, e.sessionId(), got);
                }
                Map<String, Object> meta = new LinkedHashMap<>();
                for (Map.Entry<String, Object> m : e.meta().entrySet()) meta.put(m.getKey(), m.getValue());
                subset("event " + i + " meta", obj(w.get("meta")), meta, got);
                for (Object v : meta.values()) {
                    assertTrue("no ID number in meta: " + meta, !(v instanceof String) || !((String) v).matches(".*[0-9]{8}.*") || ((String) v).matches("^[0-9a-f]{32}$"));
                }
            }
        }
        if (s.containsKey("rateLimitKeys")) {
            List<String> want = new ArrayList<>();
            for (Object k : arr(s.get("rateLimitKeys"))) want.add((String) k);
            assertEquals("rateLimitKeys", want, new ArrayList<>(keys));
        }
    }

    static Got send(EidLogin login, Map<String, Object> rq, List<Got> got, String cookieName, boolean noClientIp) {
        Map<String, List<String>> h = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : obj(rq.get("headers")).entrySet()) h.put(e.getKey(), List.of(str(e.getValue())));
        String body = null;
        if (rq.containsKey("json")) {
            h.putIfAbsent("Content-Type", List.of("application/json"));
            body = LoginJson.stringify(rq.get("json"));
        } else if (rq.containsKey("text")) {
            body = str(rq.get("text"));
        }
        if (rq.containsKey("cookieFrom")) {
            Got from = got.get(num(rq.get("cookieFrom")));
            String ck = cookieName + "=" + from.cookieValue;
            if (rq.containsKey("cookieHeader")) ck = str(rq.get("cookieHeader")).replace("$cookieFrom", ck);
            h.put("Cookie", List.of(ck));
        }
        EidLoginResponse res = login.handle(EidLoginRequest.of(str(rq.get("method")), HOST + str(rq.get("path")), h, body,
            noClientIp ? "" : str(rq.get("ip"))));
        Got g = new Got();
        g.res = res;
        if (!res.body().isEmpty() && res.header("Content-Type") != null && res.header("Content-Type").startsWith("application/json")) {
            g.json = obj(LoginJson.parse(res.body().getBytes(StandardCharsets.UTF_8)));
        }
        for (String sc : res.headers().getOrDefault("Set-Cookie", List.of())) {
            if (!sc.startsWith(cookieName + "=")) continue;
            String[] parts = sc.split("; ");
            g.cookieValue = parts[0].substring(cookieName.length() + 1);
            g.cookieAttrs = new LinkedHashMap<>();
            for (int i = 1; i < parts.length; i++) {
                int eq = parts[i].indexOf('=');
                if (eq < 0) g.cookieAttrs.put(parts[i], Boolean.TRUE);
                else g.cookieAttrs.put(parts[i].substring(0, eq), parts[i].substring(eq + 1));
            }
        }
        return g;
    }

    static void check(String at, Map<String, Object> e, Got g, List<Got> got) {
        EidLoginResponse r = g.res;
        if (e.containsKey("status")) assertEquals(at + " status (" + r.body() + ")", num(e.get("status")), r.status());
        if (e.containsKey("json")) {
            assertNotNull(at + " JSON body", g.json);
            subset(at + " json", obj(e.get("json")), g.json, got);
        }
        if (e.containsKey("jsonKeys")) {
            TreeSet<String> want = new TreeSet<>();
            for (Object k : arr(e.get("jsonKeys"))) want.add((String) k);
            assertEquals(at + " jsonKeys", want, new TreeSet<>(g.json.keySet()));
        }
        if (e.containsKey("sameKeysAs")) {
            assertEquals(at + " sameKeysAs", new TreeSet<>(got.get(num(e.get("sameKeysAs"))).json.keySet()), new TreeSet<>(g.json.keySet()));
        }
        if (e.containsKey("location")) match(at + " location", e.get("location"), r.header("Location"), got);
        for (Map.Entry<String, Object> h : obj(e.get("headers")).entrySet()) {
            assertEquals(at + " header " + h.getKey(), h.getValue(), r.header(h.getKey()));
        }
        if (Boolean.TRUE.equals(e.get("noSetCookie"))) assertTrue(at + " no Set-Cookie: " + r.headers(), g.cookieValue == null);
        if (e.containsKey("setCookie")) {
            Map<String, Object> sc = obj(e.get("setCookie"));
            assertNotNull(at + " Set-Cookie", g.cookieValue);
            if (Boolean.TRUE.equals(sc.get("cleared"))) {
                assertEquals(at + " cleared value", "", g.cookieValue);
                assertEquals(at + " cleared Max-Age", "0", g.cookieAttrs.get("Max-Age"));
            }
            if (sc.containsKey("value")) match(at + " cookie value", sc.get("value"), g.cookieValue, got);
            for (Object a : arr(sc.get("absentAttributes"))) {
                for (String k : g.cookieAttrs.keySet()) {
                    assertTrue(at + " cookie attribute " + a + " must be absent", !k.equalsIgnoreCase((String) a));
                }
            }
            for (Map.Entry<String, Object> a : obj(sc.get("attributes")).entrySet()) {
                Object want = a.getValue();
                Object have = g.cookieAttrs.get(a.getKey());
                if (want instanceof Boolean) assertEquals(at + " cookie " + a.getKey(), want, have != null);
                else match(at + " cookie " + a.getKey(), want, have, got);
            }
        }
    }

    static void subset(String at, Map<String, Object> want, Map<String, Object> have, List<Got> got) {
        for (Map.Entry<String, Object> e : want.entrySet()) {
            assertTrue(at + "." + e.getKey() + " missing in " + have, have.containsKey(e.getKey()));
            match(at + "." + e.getKey(), e.getValue(), have.get(e.getKey()), got);
        }
    }

    /** {"$re"} on the string form, {"$range": [a, b]}, {"$sameAs": "N.json.key"}; numbers by value; else equality. */
    static void match(String at, Object want, Object have, List<Got> got) {
        if (want instanceof Map) {
            Map<String, Object> m = obj(want);
            if (m.containsKey("$re")) {
                assertNotNull(at, have);
                String s = form(have);
                assertTrue(at + ": " + s + " !~ " + m.get("$re"), java.util.regex.Pattern.compile(str(m.get("$re"))).matcher(s).find());
                return;
            }
            if (m.containsKey("$range")) {
                List<Object> r = arr(m.get("$range"));
                BigDecimal v = new BigDecimal(form(have));
                assertTrue(at + ": " + v + " ∉ " + r, v.compareTo((BigDecimal) r.get(0)) >= 0 && v.compareTo((BigDecimal) r.get(1)) <= 0);
                return;
            }
            if (m.containsKey("$sameAs")) {
                String[] p = str(m.get("$sameAs")).split("\\.", 3);
                Object ref = got.get(Integer.parseInt(p[0])).json.get(p[2]);
                assertEquals(at + " $sameAs", form(ref), form(have));
                return;
            }
            subset(at, m, obj(have), got);
            return;
        }
        if (want instanceof BigDecimal) {
            assertTrue(at + ": number expected, got " + have, have instanceof BigDecimal || have instanceof Number);
            assertEquals(at, 0, ((BigDecimal) want).compareTo(new BigDecimal(have.toString())));
            return;
        }
        assertEquals(at, want, have);
    }

    static String form(Object v) {
        if (v instanceof BigDecimal) return ((BigDecimal) v).toPlainString();
        return v == null ? "null" : v.toString();
    }

    @Test
    public void corpusIsPinned() throws Exception {
        // The manifest pins every vendored file's SHA-256 (scripts/sync-conformance.sh --check keeps it byte-identical).
        try (InputStream in = getClass().getResourceAsStream("/conformance/manifest.json")) {
            Map<String, Object> m = obj(LoginJson.parse(in.readAllBytes()));
            String want = str(obj(m.get("files")).get("eidlogin/scenarios.json"));
            byte[] raw;
            try (InputStream s = getClass().getResourceAsStream("/conformance/eidlogin/scenarios.json")) {
                raw = s.readAllBytes();
            }
            assertEquals(want, hex(java.security.MessageDigest.getInstance("SHA-256").digest(raw)));
        }
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }
}
