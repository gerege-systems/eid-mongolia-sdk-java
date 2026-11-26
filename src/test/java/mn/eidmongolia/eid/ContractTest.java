package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Contract test against the LIVE {@code https://rp.eidmongolia.mn/.well-known/eid} (Go contract_test.go, TS
 * contract.test.ts). Needs the network, so it runs only with {@code EID_CONTRACT=1} (workflow contract.yml: daily +
 * manual + PR); a plain {@code ./gradlew test} skips it. No secrets — discovery is public.
 */
public class ContractTest {
    static final String DISCOVERY_URL = "https://rp.eidmongolia.mn/.well-known/eid";
    static final Pattern ENDPOINT = Pattern.compile("^(GET|POST|PUT|PATCH|DELETE)\\s+(https?://\\S+)");
    static final Pattern PLACEHOLDER = Pattern.compile("\\{[^}]*\\}");

    static Json.Obj discovery;

    @BeforeClass
    public static void fetch() throws Exception {
        assumeTrue("EID_CONTRACT=1 үед л (сүлжээ)", "1".equals(System.getenv("EID_CONTRACT")));
        HttpClient c = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(20)).build();
        HttpResponse<byte[]> r = c.send(HttpRequest.newBuilder(URI.create(DISCOVERY_URL)).timeout(Duration.ofSeconds(20))
            .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals("GET " + DISCOVERY_URL, 200, r.statusCode());
        discovery = (Json.Obj) Json.parse(r.body());
    }

    /** "METHOD /path/{}" (query dropped, {param} names ignored). */
    static String norm(String method, String path) {
        int q = path.indexOf('?');
        if (q >= 0) path = path.substring(0, q);
        return method + " " + PLACEHOLDER.matcher(path).replaceAll("{}");
    }

    /** Every "METHOD URL …" string in the endpoints tree (description lines too). */
    static void collect(Object v, List<String[]> out) {
        if (v instanceof Json.Obj) {
            for (Object x : ((Json.Obj) v).values) collect(x, out);
        } else if (v instanceof String) {
            Matcher m = ENDPOINT.matcher((String) v);
            if (m.find()) out.add(new String[] {m.group(1), m.group(2)});
        }
    }

    static void warn(String title, List<String> lines) {
        for (String l : lines) System.err.println("WARN: " + title + ": " + l);
        if (!lines.isEmpty() && "true".equals(System.getenv("GITHUB_ACTIONS"))) {
            System.out.println("::warning title=" + title + "::" + String.join("%0A", lines));
        }
    }

    @Test
    public void routes() {
        String rpBase = discovery.optString("rp_api_base");
        assertEquals("rp_api_base ≠ SDK DEFAULT_BASE_URL", EidClient.DEFAULT_BASE_URL, rpBase);
        List<String[]> eps = new ArrayList<>();
        collect(discovery.optObj("endpoints"), eps);
        assertTrue("discovery endpoints хоосон / танигдаагүй", !eps.isEmpty());
        Set<String> rp = new HashSet<>();
        Map<String[], String> keyOf = new HashMap<>();
        for (String[] e : eps) {
            if (e[1].startsWith(rpBase + "/")) {
                String k = norm(e[0], e[1].substring(rpBase.length()));
                rp.add(k);
                keyOf.put(e, k);
            }
        }
        Set<String> covered = new HashSet<>();
        List<String> missing = new ArrayList<>();
        for (Routes.Route r : Routes.ALL) {
            String k = norm(r.method(), r.path());
            covered.add(k);
            if (!rp.contains(k)) missing.add(r.method() + " " + r.path());
        }
        List<String> undiscovered = new ArrayList<>();
        List<String> nowDiscovered = new ArrayList<>();
        for (Routes.Route r : Routes.UNDISCOVERED) {
            String k = norm(r.method(), r.path());
            covered.add(k);
            (rp.contains(k) ? nowDiscovered : undiscovered).add(r.method() + " " + r.path());
        }
        warn("SDK зам CA-д бий ч discovery-д алга", undiscovered);
        warn("discovery-д орсон — Routes.UNDISCOVERED-оос Routes.ALL руу шилжүүл", nowDiscovered);
        TreeSet<String> uncovered = new TreeSet<>();
        for (String[] e : eps) {
            String k = keyOf.get(e);
            if (k == null || !covered.contains(k)) uncovered.add(e[0] + " " + e[1]);
        }
        warn("discovery-д байгаа ч SDK хамраагүй", new ArrayList<>(uncovered));
        assertTrue("SDK зам discovery-д алга: " + missing, missing.isEmpty());
        System.out.println("SDK " + Routes.ALL.size() + " зам тулгав (+" + Routes.UNDISCOVERED.size() + " discovery-гүй); discovery-д SDK хамраагүй "
            + uncovered.size() + " (WARN)");
    }

    @Test
    public void pdfRegisterErrorCodes() {
        Json.Obj pdf = discovery.optObj("pdfSigning");
        assertNotNull("pdfSigning discovery-д алга", pdf);
        List<Object> codes = pdf.optArr("registerErrorCodes");
        assertNotNull("pdfSigning.registerErrorCodes discovery-д алга", codes);
        TreeSet<String> ca = new TreeSet<>();
        for (Object o : codes) ca.add((String) o);
        assertEquals("CA ↔ SDK кодын олонлог", ca, new TreeSet<>(EidErrorCodes.PDF_REGISTER));
    }

    @Test
    public void sealSwitchesAndCodes() {
        Json.Obj s = discovery.optObj("seal");
        assertNotNull("discovery-д seal блок алга", s);
        assertTrue("seal.issuanceEnabled", s.get("issuanceEnabled") instanceof Boolean);
        assertTrue("seal.sealingEnabled", s.get("sealingEnabled") instanceof Boolean);
        assertEquals(EidErrorCodes.SEAL_SERVICE_DISABLED, s.optString("disabledCode"));

        Json.Obj seal = discovery.optObj("endpoints").optObj("seal");
        assertNotNull("endpoints.seal", seal);
        Pattern code = Pattern.compile("\\b(?:ORG_NOT_ACTIVE|SEAL_[A-Z_]+)\\b");
        Set<String> known = new HashSet<>(EidErrorCodes.SEAL);
        known.addAll(EidErrorCodes.SEAL_GRANT);
        Map<String, Set<String>> named = new HashMap<>();
        List<String> unknown = new ArrayList<>();
        for (int i = 0; i < seal.keys.size(); i++) {
            String key = seal.keys.get(i);
            Object v = seal.values.get(i);
            Set<String> got = named.computeIfAbsent(key, x -> new HashSet<>());
            if (!(v instanceof String)) continue;
            Matcher m = code.matcher((String) v);
            while (m.find()) {
                got.add(m.group());
                if (!known.contains(m.group())) unknown.add("endpoints.seal." + key + ": " + m.group());
            }
        }
        assertTrue("SDK-д танигдаагүй code: " + unknown, unknown.isEmpty());
        Map<String, List<String>> want = Map.of(
            "seal", List.of("ORG_NOT_ACTIVE", "SEAL_NOT_ISSUED", "SEAL_CERT_REVOKED", "SEAL_KEY_UNAVAILABLE", "SEAL_CERT_EXPIRED",
                "SEAL_CERT_NOT_YET_VALID", "SEAL_SERVICE_DISABLED"),
            "certificate_get", List.of("SEAL_NOT_ISSUED", "SEAL_CERT_REVOKED", "SEAL_CERT_EXPIRED", "SEAL_CERT_NOT_YET_VALID"),
            "certificate_issue", List.of("ORG_NOT_ACTIVE", "SEAL_APPROVER_UNAVAILABLE", "SEAL_SERVICE_DISABLED"),
            "grant_request", List.of("ORG_NOT_ACTIVE", "SEAL_GRANT_ALREADY_APPROVED", "SEAL_APPROVER_UNAVAILABLE"),
            "grant_status", List.of("SEAL_GRANT_NOT_FOUND"));
        List<String> absent = new ArrayList<>();
        for (Map.Entry<String, List<String>> e : want.entrySet()) {
            for (String c : e.getValue()) {
                if (!named.getOrDefault(e.getKey(), Set.of()).contains(c)) absent.add("endpoints.seal." + e.getKey() + " ∌ " + c);
            }
        }
        assertTrue(absent.toString(), absent.isEmpty());
    }

    @Test
    public void sessionTtlPublished() {
        Json.Obj t = discovery.optObj("sessionTtl");
        assertNotNull("discovery-д sessionTtl алга", t);
        assertTrue("sessionTtl.auth", t.optLong("auth", 0) > 0);
        assertTrue("sessionTtl.sign", t.optLong("sign", 0) > 0);
    }
}
