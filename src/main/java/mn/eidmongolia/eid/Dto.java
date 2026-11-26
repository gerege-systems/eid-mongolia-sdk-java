package mn.eidmongolia.eid;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Response-field readers shared by the RP services (the Go {@code decodeJSON} into typed structs): absent members take
 * the zero value ("" / 0 / false / null / empty list); a timestamp that is present but not RFC 3339 fails the call like
 * Go's {@code time.Time} unmarshalling does.
 */
final class Dto {
    private Dto() {
    }

    /** The raw body as text ("" for an empty body). */
    static String raw(RpHttp.Result r) {
        return new String(r.raw(), StandardCharsets.UTF_8);
    }

    /** RFC 3339 member → Instant; absent / null → null; anything else → {@link EidException}. */
    static Instant instant(Json.Obj o, String k, String op) {
        Object v = o.get(k);
        if (v == null || v == Json.NULL) return null;
        if (!(v instanceof String)) throw new EidException("eid: " + op + ": " + k + " огноо биш");
        try {
            return OffsetDateTime.parse((String) v).toInstant();
        } catch (DateTimeParseException e) {
            throw new EidException("eid: " + op + ": " + k + " RFC 3339 биш", e);
        }
    }

    /** An integer member clamped to int (absent / not an integer → 0). */
    static int integer(Json.Obj o, String k) {
        long v = o.optLong(k, 0);
        return (int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, v));
    }

    /** An integer member or null when absent / not an integer (Go *int64). */
    static Long optLongOrNull(Json.Obj o, String k) {
        Object v = o.get(k);
        return v instanceof Json.Num ? ((Json.Num) v).exactLong() : null;
    }

    /** The object members of an array member (other elements skipped); absent → empty. */
    static List<Json.Obj> objects(Json.Obj o, String k) {
        List<Object> a = o.optArr(k);
        if (a == null) return List.of();
        List<Json.Obj> out = new ArrayList<>();
        for (Object x : a) if (x instanceof Json.Obj) out.add((Json.Obj) x);
        return out;
    }

    /** The string elements of an array member; absent → empty. */
    static List<String> strings(Json.Obj o, String k) {
        List<Object> a = o.optArr(k);
        if (a == null) return List.of();
        List<String> out = new ArrayList<>();
        for (Object x : a) if (x instanceof String) out.add((String) x);
        return Collections.unmodifiableList(out);
    }

    /** An object member, or an empty object when absent. */
    static Json.Obj obj(Json.Obj o, String k) {
        Json.Obj v = o.optObj(k);
        return v == null ? new Json.Obj() : v;
    }

    /** A parsed JSON value back to text (raw sub-blocks such as discovery's share / tokenCertificate). */
    static String text(Object v) {
        return Json.stringify(plain(v));
    }

    private static Object plain(Object v) {
        if (v instanceof Json.Obj) {
            Json.Obj o = (Json.Obj) v;
            java.util.Map<String, Object> m = new java.util.LinkedHashMap<>();
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
}
