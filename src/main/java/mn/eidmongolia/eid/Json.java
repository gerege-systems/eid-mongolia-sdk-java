package mn.eidmongolia.eid;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Minimal strict RFC 8259 JSON reader/writer for the RP-API client (no dependency). The reader is the same as
 * {@code mn.eidmongolia.eid.pades.Json} (objects keep member order and duplicates, the last one wins in
 * {@link Obj#get}; numbers keep their text). Values: {@link Obj}, {@link List}, String, {@link Num}, Boolean,
 * {@link #NULL}.
 *
 * <p>The writer ({@link #stringify}) produces the bytes of JavaScript {@code JSON.stringify} (ECMA-262
 * QuoteJSONString): {@code "} and {@code \} escaped, {@code \b \f \n \r \t} short escapes, other controls
 * as a six-character backslash-u escape with lower-case hex, lone surrogates likewise, everything else — {@code < > &}, U+2028/U+2029,
 * non-ASCII — written raw. {@link EidCrypto#interactionsToBase64} relies on this byte for byte (TS SDK
 * {@code interactionsToBase64}, Go {@code crypto.go} {@code InteractionsToBase64}).
 */
final class Json {
    private Json() {
    }

    static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    static final int MAX_DEPTH = 64;

    /** A JSON number as written. */
    static final class Num {
        final String text;

        Num(String text) {
            this.text = text;
        }

        /** The exact integer value, or null when it is not an integer that fits a long (e.g. 1.5, 1e3, 2^63). */
        Long exactLong() {
            for (int i = 0; i < text.length(); i++) {
                char c = text.charAt(i);
                if (c == '.' || c == 'e' || c == 'E') return null;
            }
            try {
                return Long.parseLong(text);
            } catch (NumberFormatException e) {
                return null;
            }
        }

        long longValue() {
            Long v = exactLong();
            if (v != null) return v;
            return new BigDecimal(text).longValueExact();
        }
    }

    static final class Obj {
        final List<String> keys = new ArrayList<>();
        final List<Object> values = new ArrayList<>();

        Object get(String k) {
            for (int i = keys.size() - 1; i >= 0; i--) if (keys.get(i).equals(k)) return values.get(i);
            return null;
        }

        boolean has(String k) {
            return get(k) != null;
        }

        Set<String> keySet() {
            return new LinkedHashSet<>(keys);
        }

        /** The string member, else "" (absent, null or another type). */
        String optString(String k) {
            Object v = get(k);
            return v instanceof String ? (String) v : "";
        }

        /** The string member, else null (absent, null or another type). */
        String optStringOrNull(String k) {
            Object v = get(k);
            return v instanceof String ? (String) v : null;
        }

        Obj optObj(String k) {
            Object v = get(k);
            return v instanceof Obj ? (Obj) v : null;
        }

        @SuppressWarnings("unchecked")
        List<Object> optArr(String k) {
            Object v = get(k);
            return v instanceof List ? (List<Object>) v : null;
        }

        /** The integer member, else def (absent, another type, or not an integer that fits a long). */
        long optLong(String k, long def) {
            Object v = get(k);
            if (!(v instanceof Num)) return def;
            Long l = ((Num) v).exactLong();
            return l == null ? def : l;
        }

        boolean optBool(String k, boolean def) {
            Object v = get(k);
            return v instanceof Boolean ? (Boolean) v : def;
        }
    }

    // ── reader ──

    /** Parses UTF-8 bytes strictly (invalid UTF-8 → IllegalArgumentException). */
    static Object parse(byte[] utf8) {
        String s;
        try {
            s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(utf8)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("JSON: invalid UTF-8");
        }
        return parse(s);
    }

    static Object parse(String s) {
        Reader r = new Reader(s);
        int start = 0;
        if (s.length() > 0 && s.charAt(0) == '﻿') start = 1;
        r.p = start;
        r.ws();
        Object v = r.value(0);
        r.ws();
        if (r.p != s.length()) throw r.err("trailing data");
        return v;
    }

    private static int hexVal(int c) {
        if (c >= 0x30 && c <= 0x39) return c - 0x30;
        if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
        if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
        return -1;
    }

    private static final class Reader {
        final String s;
        int p;

        Reader(String s) {
            this.s = s;
        }

        IllegalArgumentException err(String m) {
            return new IllegalArgumentException("JSON: " + m + " at " + p);
        }

        void ws() {
            while (p < s.length()) {
                char c = s.charAt(p);
                if (c == ' ' || c == '\t' || c == '\n' || c == '\r') p++;
                else break;
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) throw err("nesting too deep");
            if (p >= s.length()) throw err("unexpected end");
            char c = s.charAt(p);
            switch (c) {
                case '{': {
                    p++;
                    Obj o = new Obj();
                    ws();
                    if (p < s.length() && s.charAt(p) == '}') {
                        p++;
                        return o;
                    }
                    while (true) {
                        ws();
                        if (p >= s.length() || s.charAt(p) != '"') throw err("object key expected");
                        String k = string();
                        ws();
                        if (p >= s.length() || s.charAt(p) != ':') throw err("':' expected");
                        p++;
                        ws();
                        Object v = value(depth + 1);
                        o.keys.add(k);
                        o.values.add(v);
                        ws();
                        if (p >= s.length()) throw err("unterminated object");
                        char d = s.charAt(p++);
                        if (d == '}') return o;
                        if (d != ',') throw err("',' or '}' expected");
                    }
                }
                case '[': {
                    p++;
                    List<Object> a = new ArrayList<>();
                    ws();
                    if (p < s.length() && s.charAt(p) == ']') {
                        p++;
                        return a;
                    }
                    while (true) {
                        ws();
                        a.add(value(depth + 1));
                        ws();
                        if (p >= s.length()) throw err("unterminated array");
                        char d = s.charAt(p++);
                        if (d == ']') return a;
                        if (d != ',') throw err("',' or ']' expected");
                    }
                }
                case '"':
                    return string();
                case 't':
                    return literal("true", Boolean.TRUE);
                case 'f':
                    return literal("false", Boolean.FALSE);
                case 'n':
                    return literal("null", NULL);
                default:
                    return number();
            }
        }

        Object literal(String w, Object v) {
            if (!s.startsWith(w, p)) throw err("bad literal");
            p += w.length();
            return v;
        }

        Num number() {
            int st = p;
            if (p < s.length() && s.charAt(p) == '-') p++;
            if (p >= s.length()) throw err("bad number");
            if (s.charAt(p) == '0') {
                p++;
            } else if (s.charAt(p) >= '1' && s.charAt(p) <= '9') {
                while (p < s.length() && s.charAt(p) >= '0' && s.charAt(p) <= '9') p++;
            } else {
                throw err("bad number");
            }
            if (p < s.length() && s.charAt(p) == '.') {
                p++;
                int d = p;
                while (p < s.length() && s.charAt(p) >= '0' && s.charAt(p) <= '9') p++;
                if (p == d) throw err("bad number");
            }
            if (p < s.length() && (s.charAt(p) == 'e' || s.charAt(p) == 'E')) {
                p++;
                if (p < s.length() && (s.charAt(p) == '+' || s.charAt(p) == '-')) p++;
                int d = p;
                while (p < s.length() && s.charAt(p) >= '0' && s.charAt(p) <= '9') p++;
                if (p == d) throw err("bad number");
            }
            return new Num(s.substring(st, p));
        }

        String string() {
            p++; // opening quote
            StringBuilder sb = new StringBuilder();
            while (true) {
                if (p >= s.length()) throw err("unterminated string");
                char c = s.charAt(p++);
                if (c == '"') return sb.toString();
                if (c < 0x20) throw err("control character in string");
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                if (p >= s.length()) throw err("unterminated escape");
                char e = s.charAt(p++);
                switch (e) {
                    case '"': sb.append('"'); break;
                    case '\\': sb.append('\\'); break;
                    case '/': sb.append('/'); break;
                    case 'b': sb.append('\b'); break;
                    case 'f': sb.append('\f'); break;
                    case 'n': sb.append('\n'); break;
                    case 'r': sb.append('\r'); break;
                    case 't': sb.append('\t'); break;
                    case 'u': {
                        if (p + 4 > s.length()) throw err("bad \\u escape");
                        int v = 0;
                        for (int k = 0; k < 4; k++) {
                            int h = hexVal(s.charAt(p + k));
                            if (h < 0) throw err("bad \\u escape");
                            v = (v << 4) | h;
                        }
                        p += 4;
                        sb.append((char) v);
                        break;
                    }
                    default:
                        throw err("bad escape");
                }
            }
        }
    }

    // ── writer ──

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /**
     * Serialises a value the way JavaScript {@code JSON.stringify} does (no whitespace). Accepted values: null /
     * {@link #NULL}, String, Boolean, Integer / Long / BigInteger, {@link Map} with String keys (iteration order kept;
     * null values are skipped like JS {@code undefined}), {@link Collection} (null elements → {@code null}).
     */
    static String stringify(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v, 0);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object v, int depth) {
        if (depth > MAX_DEPTH) throw new IllegalArgumentException("JSON: nesting too deep");
        if (v == null || v == NULL) {
            sb.append("null");
        } else if (v instanceof String) {
            quote(sb, (String) v);
        } else if (v instanceof Boolean) {
            sb.append(((Boolean) v) ? "true" : "false");
        } else if (v instanceof Integer || v instanceof Long || v instanceof BigInteger) {
            sb.append(v.toString());
        } else if (v instanceof Num) {
            sb.append(((Num) v).text);
        } else if (v instanceof Map) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (e.getValue() == null) continue;
                if (!(e.getKey() instanceof String)) throw new IllegalArgumentException("JSON: object key is not a string");
                if (!first) sb.append(',');
                first = false;
                quote(sb, (String) e.getKey());
                sb.append(':');
                write(sb, e.getValue(), depth + 1);
            }
            sb.append('}');
        } else if (v instanceof Collection) {
            sb.append('[');
            boolean first = true;
            for (Object x : (Collection<?>) v) {
                if (!first) sb.append(',');
                first = false;
                write(sb, x, depth + 1);
            }
            sb.append(']');
        } else {
            throw new IllegalArgumentException("JSON: unsupported value type " + v.getClass().getName());
        }
    }

    /** Appends {@code s} as a JSON string, byte-identical to JavaScript {@code JSON.stringify} (ECMA-262 QuoteJSONString). */
    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); continue;
                case '\\': sb.append("\\\\"); continue;
                case '\b': sb.append("\\b"); continue;
                case '\f': sb.append("\\f"); continue;
                case '\n': sb.append("\\n"); continue;
                case '\r': sb.append("\\r"); continue;
                case '\t': sb.append("\\t"); continue;
                default:
                    break;
            }
            if (c < 0x20) {
                unicodeEscape(sb, c);
            } else if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    sb.append(c).append(s.charAt(++i));
                } else {
                    unicodeEscape(sb, c); // lone high surrogate (well-formed JSON.stringify, ES2019)
                }
            } else if (Character.isLowSurrogate(c)) {
                unicodeEscape(sb, c); // lone low surrogate
            } else {
                sb.append(c);
            }
        }
        sb.append('"');
    }

    private static void unicodeEscape(StringBuilder sb, char c) {
        sb.append("\\u").append(HEX[(c >> 12) & 0xF]).append(HEX[(c >> 8) & 0xF]).append(HEX[(c >> 4) & 0xF]).append(HEX[c & 0xF]);
    }
}
