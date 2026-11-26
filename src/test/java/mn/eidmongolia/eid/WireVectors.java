package mn.eidmongolia.eid;

import java.util.ArrayList;
import java.util.List;

/**
 * Wire vectors: one RP-API call each — the SDK operation and its input, the expected HTTP method / path / query /
 * request-body JSON (compared semantically), a canned response, and the expected parsed result (or typed error).
 *
 * <p>{@link #LOCAL} carries hand-ported cases from the Go/TS test suites (each names its source test). The cross-SDK
 * conformance corpus (Go testdata/conformance, vendored unedited under src/test/resources/conformance by
 * scripts/sync-conformance.sh) has its own wire format (README §wire: exact path + query, headers, volatile values,
 * a whole-result expectation); {@link ConformanceTest#wire} runs it through the same operation map
 * ({@link WireVectorTest#OPS}).
 */
final class WireVectors {
    private WireVectors() {
    }

    /**
     * One wire case.
     *
     * @param op the SDK operation, e.g. "auth.notificationByEtsi" ({@link WireVectorTest} maps it to a call)
     * @param input the operation's arguments (JSON object)
     * @param query the expected raw query, null = none
     * @param requestBody the expected body (semantic JSON; "&lt;any&gt;" matches any non-empty string), null = no body
     * @param expect projected result fields, or error.class / error.code / error.status
     */
    record Vector(String name, String source, String op, Json.Obj input, String method, String path, String query,
        Object requestBody, int status, Object responseBody, Json.Obj expect) {
        @Override
        public String toString() {
            return name + " (" + source + ")";
        }
    }

    /** A provider of vectors (local hand-ported file now, the conformance corpus later). */
    interface Source {
        String name();

        List<Vector> vectors();
    }

    /** A vector file in the local format (src/test/resources/wire/rp-wire-local.json). */
    static Source resource(String path) {
        return new Source() {
            @Override
            public String name() {
                return path;
            }

            @Override
            public List<Vector> vectors() {
                Json.Obj root = (Json.Obj) Json.parse(TestRes.resource(path));
                List<Vector> out = new ArrayList<>();
                for (Object o : root.optArr("vectors")) {
                    Json.Obj v = (Json.Obj) o;
                    Json.Obj req = v.optObj("request");
                    Json.Obj res = v.optObj("response");
                    Object body = req.get("body");
                    out.add(new Vector(v.optString("name"), v.optString("source"), v.optString("op"), v.optObj("input"),
                        req.optString("method"), req.optString("path"), req.optStringOrNull("query"),
                        body == Json.NULL ? null : body, (int) res.optLong("status", 0), res.get("body"), v.optObj("expect")));
                }
                return out;
            }
        };
    }

    static final Source LOCAL = resource("wire/rp-wire-local.json");
}
