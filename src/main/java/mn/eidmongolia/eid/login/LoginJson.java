package mn.eidmongolia.eid.login;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The login handler's JSON: a strict reader for the small POST /start body and a writer for the answers (the JS
 * {@code JSON.stringify} escaping of the core {@code Json}). Package-private — the core's JSON is not exported.
 */
final class LoginJson {
    private LoginJson() {
    }

    static final Object NULL = new Object();
    private static final int MAX_DEPTH = 32;

    /** Parses strict UTF-8 JSON: objects → LinkedHashMap, arrays → List, numbers → BigDecimal, null → {@link #NULL}. */
    static Object parse(byte[] utf8) {
        String s;
        try {
            s = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(utf8)).toString();
        } catch (CharacterCodingException e) {
            throw new IllegalArgumentException("JSON: invalid UTF-8");
        }
        Reader r = new Reader(s);
        r.ws();
        Object v = r.value(0);
        r.ws();
        if (r.p != s.length()) throw new IllegalArgumentException("JSON: trailing data");
        return v;
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
                if (c != ' ' && c != '\t' && c != '\n' && c != '\r') break;
                p++;
            }
        }

        Object value(int depth) {
            if (depth > MAX_DEPTH) throw err("too deep");
            if (p >= s.length()) throw err("unexpected end");
            char c = s.charAt(p);
            switch (c) {
                case '{': {
                    p++;
                    Map<String, Object> m = new LinkedHashMap<>();
                    ws();
                    if (p < s.length() && s.charAt(p) == '}') {
                        p++;
                        return m;
                    }
                    while (true) {
                        ws();
                        if (p >= s.length() || s.charAt(p) != '"') throw err("key expected");
                        String k = string();
                        ws();
                        if (p >= s.length() || s.charAt(p) != ':') throw err("':' expected");
                        p++;
                        ws();
                        m.put(k, value(depth + 1));
                        ws();
                        if (p < s.length() && s.charAt(p) == ',') {
                            p++;
                            continue;
                        }
                        if (p < s.length() && s.charAt(p) == '}') {
                            p++;
                            return m;
                        }
                        throw err("',' or '}' expected");
                    }
                }
                case '[': {
                    p++;
                    List<Object> l = new ArrayList<>();
                    ws();
                    if (p < s.length() && s.charAt(p) == ']') {
                        p++;
                        return l;
                    }
                    while (true) {
                        ws();
                        l.add(value(depth + 1));
                        ws();
                        if (p < s.length() && s.charAt(p) == ',') {
                            p++;
                            continue;
                        }
                        if (p < s.length() && s.charAt(p) == ']') {
                            p++;
                            return l;
                        }
                        throw err("',' or ']' expected");
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

        BigDecimal number() {
            int st = p;
            if (p < s.length() && s.charAt(p) == '-') p++;
            if (p >= s.length() || !Character.isDigit(s.charAt(p))) throw err("bad number");
            if (s.charAt(p) == '0') p++;
            else while (p < s.length() && s.charAt(p) >= '0' && s.charAt(p) <= '9') p++;
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
            return new BigDecimal(s.substring(st, p));
        }

        String string() {
            p++;
            StringBuilder b = new StringBuilder();
            while (true) {
                if (p >= s.length()) throw err("unterminated string");
                char c = s.charAt(p++);
                if (c == '"') return b.toString();
                if (c < 0x20) throw err("control character in string");
                if (c != '\\') {
                    b.append(c);
                    continue;
                }
                if (p >= s.length()) throw err("bad escape");
                char e = s.charAt(p++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'u':
                        if (p + 4 > s.length()) throw err("bad escape");
                        try {
                            b.append((char) Integer.parseInt(s.substring(p, p + 4), 16));
                        } catch (NumberFormatException x) {
                            throw err("bad escape");
                        }
                        p += 4;
                        break;
                    default:
                        throw err("bad escape");
                }
            }
        }
    }

    /** JSON text (JS JSON.stringify rules; Map keys must be strings; null map values skipped like undefined). */
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
        } else if (v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte
            || v instanceof java.math.BigInteger) {
            sb.append(v.toString());
        } else if (v instanceof BigDecimal) {
            sb.append(((BigDecimal) v).toString());
        } else if (v instanceof Double || v instanceof Float) {
            double d = ((Number) v).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) sb.append("null");
            else if (d == Math.rint(d) && Math.abs(d) < 1e15) sb.append((long) d);
            else sb.append(d);
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

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    boolean lone = (Character.isHighSurrogate(c) && (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))))
                        || (Character.isLowSurrogate(c) && (i == 0 || !Character.isHighSurrogate(s.charAt(i - 1))));
                    if (c < 0x20 || lone) {
                        sb.append("\\u").append(HEX[c >> 12 & 0xf]).append(HEX[c >> 8 & 0xf]).append(HEX[c >> 4 & 0xf]).append(HEX[c & 0xf]);
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
