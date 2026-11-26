package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * A recording fake RP-API (an {@link EidTransport}) with a controllable clock — the Java counterpart of the Go tests'
 * httptest {@code server(t, fn)} + {@code rec}. Requests are recorded; the handler answers.
 */
final class FakeRp implements EidTransport {
    /** Go client_test.go {@code creds}. */
    static final Credentials CREDS = new Credentials("rp-uuid", "Гэрээний систем", "rp_sk_secret123");

    final List<EidHttpRequest> seen = new ArrayList<>();
    final FakeClock clock = new FakeClock(Instant.parse("2026-10-14T12:00:00Z"));
    Function<EidHttpRequest, EidHttpResponse> handler;

    FakeRp(Function<EidHttpRequest, EidHttpResponse> handler) {
        this.handler = handler;
    }

    /** Every request gets the same JSON reply (Go {@code jsonReply}). */
    static FakeRp reply(int status, String body) {
        return new FakeRp(r -> json(status, body));
    }

    static EidHttpResponse json(int status, String body) {
        return new EidHttpResponse(status, Map.of("Content-Type", List.of("application/json")), body.getBytes(StandardCharsets.UTF_8));
    }

    EidClient client() {
        return builder().build();
    }

    EidClient.Builder builder() {
        return EidClient.builder(CREDS).transport(this).clock(clock);
    }

    @Override
    public EidHttpResponse send(EidHttpRequest request) {
        seen.add(request);
        return handler.apply(request);
    }

    EidHttpRequest last() {
        return seen.get(seen.size() - 1);
    }

    String lastBody() {
        byte[] b = last().body();
        return b == null ? "" : new String(b, StandardCharsets.UTF_8);
    }

    Json.Obj lastJson() {
        return (Json.Obj) Json.parse(last().body());
    }

    static String path(EidHttpRequest r) {
        return r.uri().getRawPath();
    }

    /** A settable clock (Go tests use time.Now; here time only moves when a test moves it). */
    static final class FakeClock extends Clock {
        Instant now;

        FakeClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    // ── semantic JSON comparison (member order ignored, numbers by value) ──

    /** In an EXPECTED string value: matches any non-empty string (random challenges). */
    static final String ANY = "<any>";

    static void assertJsonEquals(String what, String expected, String actual) {
        String d = diff("$", Json.parse(expected), Json.parse(actual));
        if (d != null) fail(what + ": " + d + "\n expected " + expected + "\n actual   " + actual);
    }

    private static String diff(String at, Object e, Object a) {
        if (e instanceof Json.Obj) {
            if (!(a instanceof Json.Obj)) return at + ": object expected";
            Json.Obj eo = (Json.Obj) e;
            Json.Obj ao = (Json.Obj) a;
            if (!eo.keySet().equals(ao.keySet())) return at + ": members " + eo.keySet() + " != " + ao.keySet();
            if (ao.keys.size() != ao.keySet().size()) return at + ": duplicate member";
            for (String k : eo.keySet()) {
                String d = diff(at + "." + k, eo.get(k), ao.get(k));
                if (d != null) return d;
            }
            return null;
        }
        if (e instanceof List) {
            if (!(a instanceof List)) return at + ": array expected";
            List<?> el = (List<?>) e;
            List<?> al = (List<?>) a;
            if (el.size() != al.size()) return at + ": length " + el.size() + " != " + al.size();
            for (int i = 0; i < el.size(); i++) {
                String d = diff(at + "[" + i + "]", el.get(i), al.get(i));
                if (d != null) return d;
            }
            return null;
        }
        if (e instanceof Json.Num) {
            if (!(a instanceof Json.Num)) return at + ": number expected";
            return new BigDecimal(((Json.Num) e).text).compareTo(new BigDecimal(((Json.Num) a).text)) == 0 ? null : at + ": number";
        }
        if (ANY.equals(e)) return a instanceof String && !((String) a).isEmpty() ? null : at + ": non-empty string expected";
        if (e instanceof String) return e.equals(a) ? null : at + ": \"" + e + "\" != " + a;
        return e == a || (e != null && e.equals(a)) ? null : at + ": " + e + " != " + a;
    }

    /** A parsed JSON value back to text (the writer does not take {@link Json.Obj}). */
    static String text(Object v) {
        return Json.stringify(plain(v));
    }

    private static Object plain(Object v) {
        if (v instanceof Json.Obj) {
            Json.Obj o = (Json.Obj) v;
            Map<String, Object> m = new java.util.LinkedHashMap<>();
            for (int i = 0; i < o.keys.size(); i++) m.put(o.keys.get(i), plain(o.values.get(i)));
            return m;
        }
        if (v instanceof List) {
            List<Object> l = new ArrayList<>();
            for (Object x : (List<?>) v) l.add(plain(x));
            return l;
        }
        return v == null ? Json.NULL : v;
    }

    static void assertRequest(EidHttpRequest r, String method, String path) {
        assertEquals("method", method, r.method());
        assertEquals("path", path, path(r));
    }
}
