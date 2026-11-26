package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;
import mn.eidmongolia.eid.pades.validate.PdfReport;
import mn.eidmongolia.eid.pades.validate.ValidatePdfException;
import mn.eidmongolia.eid.pades.validate.ValidatePdfOptions;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * ValidatePDF conformance (pades-validate/1): the Go reference's corpus (src/test/resources/pades-validate, pinned by
 * scripts/sync-pades-validate.sh) — every case's report must equal the manifest's expect field for field (TS
 * validate-golden.test.ts deep-equal: JSON objects compared regardless of member order). Online OCSP/CRL = the recorded
 * HTTP replay (key "METHOD URL hex(sha256(body))[:16]"; anything else → HTTP 404).
 */
@RunWith(Parameterized.class)
public class ValidatePdfGoldenTest {
    static final String ROOT = "/pades-validate/";

    /**
     * Cases that cannot pass yet, with the reason — reported as SKIPPED (JUnit assumption), never silently. The expected
     * report is never weakened.
     */
    static final Map<String, String> PENDING = new HashMap<>();

    static byte[] res(String path) {
        try (InputStream s = ValidatePdfGoldenTest.class.getResourceAsStream(ROOT + path)) {
            if (s == null) throw new IllegalStateException("missing test resource " + path);
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static Json.Obj manifest() {
        return (Json.Obj) Json.parse(res("validate/manifest.json"));
    }

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> cases() {
        List<Object[]> out = new ArrayList<>();
        for (Object c : (List<?>) manifest().get("cases")) out.add(new Object[] {((Json.Obj) c).getString("name"), c});
        return out;
    }

    private final String name;
    private final Json.Obj c;

    public ValidatePdfGoldenTest(String name, Object c) {
        this.name = name;
        this.c = (Json.Obj) c;
    }

    private static List<byte[]> pems(Object list) {
        List<byte[]> out = new ArrayList<>();
        for (Object p : (List<?>) list) out.add(Cert.pemSingle(res((String) p)));
        return out;
    }

    static String sha16(byte[] b) {
        try {
            return Text.hex(MessageDigest.getInstance("SHA-256").digest(b == null ? new byte[0] : b)).substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void report() {
        String why = PENDING.get(name);
        Assume.assumeTrue("PENDING " + name + ": " + why, why == null);
        Json.Obj m = manifest();
        byte[] doc = res(c.getString("input"));
        Map<String, byte[]> files = new HashMap<>();
        Object http = c.get("http");
        if (http instanceof Json.Obj) {
            Json.Obj h = (Json.Obj) http;
            for (String k : h.keySet()) files.put(k, res("validate/" + h.getString(k)));
        }
        EidPadesTransport replay = (method, url, ct, body) -> {
            byte[] b = files.get(method + " " + url + " " + sha16(body));
            if (b == null) throw new IOException(url + ": HTTP 404");
            return b;
        };
        boolean national = Boolean.TRUE.equals(c.get("nationalRoots"));
        String time = c.optNonEmpty("time") != null ? c.getString("time") : m.getString("time");
        ValidatePdfOptions o = ValidatePdfOptions.builder()
            .roots(national ? List.of() : pems(m.get("roots")))
            .issuers(pems(m.get("issuers")))
            .time(Instant.parse(time))
            .offline(Boolean.TRUE.equals(c.get("offline")))
            .transport(replay)
            .build();
        String got;
        try {
            PdfReport r = EidPades.validatePdf(doc, o);
            got = r.toJson();
        } catch (ValidatePdfException e) {
            got = "{\"error\":\"" + e.code() + "\"}";
        }
        String want = canon(c.get("expect"));
        String have = canon(Json.parse(got.getBytes(StandardCharsets.UTF_8)));
        assertEquals(name, want, have);
    }

    /** Canonical JSON: object members sorted (deep-equal regardless of order), arrays in order. */
    static String canon(Object v) {
        StringBuilder b = new StringBuilder();
        canon(v, b);
        return b.toString();
    }

    private static void canon(Object v, StringBuilder b) {
        if (v instanceof Json.Obj) {
            Json.Obj o = (Json.Obj) v;
            TreeMap<String, Object> t = new TreeMap<>();
            for (String k : o.keySet()) t.put(k, o.get(k));
            b.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : t.entrySet()) {
                if (!first) b.append(',');
                first = false;
                b.append(Json.quote(e.getKey())).append(':');
                canon(e.getValue(), b);
            }
            b.append("}\n");
        } else if (v instanceof List) {
            b.append('[');
            boolean first = true;
            for (Object x : (List<?>) v) {
                if (!first) b.append(',');
                first = false;
                canon(x, b);
            }
            b.append(']');
        } else if (v instanceof String) {
            b.append(Json.quote((String) v));
        } else if (v instanceof Json.Num) {
            b.append(((Json.Num) v).text);
        } else {
            b.append(v == Json.NULL ? "null" : String.valueOf(v));
        }
    }
}
