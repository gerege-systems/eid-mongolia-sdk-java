package mn.eidmongolia.eid.pades;

import java.math.BigDecimal;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import mn.eidmongolia.eid.internal.Text;

/**
 * Minimal strict RFC 8259 JSON reader/writer (no dependency). Objects keep member order and duplicates (the last one
 * wins in [Obj.get]); numbers keep their text. Values: [Obj], [List], String, [Num], Boolean, [NULL].
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

        double doubleValue() {
            return Double.parseDouble(text);
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

        private Object need(String k) {
            Object v = get(k);
            if (v == null) throw new IllegalArgumentException("JSON member " + k + " missing");
            return v;
        }

        String getString(String k) {
            Object v = need(k);
            if (!(v instanceof String)) throw new IllegalArgumentException("JSON member " + k + " is not a string");
            return (String) v;
        }

        /** The string member, else "" (absent, null or another type). */
        String optString(String k) {
            Object v = get(k);
            return v instanceof String ? (String) v : "";
        }

        /** The string member, else null; an empty string is null too. */
        String optNonEmpty(String k) {
            String s = optString(k);
            return s.isEmpty() ? null : s;
        }

        Obj getObj(String k) {
            Object v = need(k);
            if (!(v instanceof Obj)) throw new IllegalArgumentException("JSON member " + k + " is not an object");
            return (Obj) v;
        }

        Obj optObj(String k) {
            Object v = get(k);
            return v instanceof Obj ? (Obj) v : null;
        }

        @SuppressWarnings("unchecked")
        List<Object> getArr(String k) {
            Object v = need(k);
            if (!(v instanceof List)) throw new IllegalArgumentException("JSON member " + k + " is not an array");
            return (List<Object>) v;
        }

        @SuppressWarnings("unchecked")
        List<Object> optArr(String k) {
            Object v = get(k);
            return v instanceof List ? (List<Object>) v : null;
        }

        long getLong(String k) {
            Object v = need(k);
            if (!(v instanceof Num)) throw new IllegalArgumentException("JSON member " + k + " is not a number");
            return ((Num) v).longValue();
        }

        int getInt(String k) {
            return Math.toIntExact(getLong(k));
        }

        int optInt(String k, int def) {
            Object v = get(k);
            return v instanceof Num ? Math.toIntExact(((Num) v).longValue()) : def;
        }

        double getDouble(String k) {
            Object v = need(k);
            if (!(v instanceof Num)) throw new IllegalArgumentException("JSON member " + k + " is not a number");
            return ((Num) v).doubleValue();
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
                while (p < s.length() && Character.isDigit(s.charAt(p)) && s.charAt(p) < 0x80) p++;
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
                            int h = Text.hexVal(s.charAt(p + k));
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

    /** Appends [s] as a JSON string (Go encoding/json escaping of '"', '\\', control chars, U+2028/U+2029). */
    static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c < 0x20 || c == ' ' || c == ' ') sb.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
            else sb.append(c);
        }
        sb.append('"');
    }

    static String quote(String s) {
        StringBuilder sb = new StringBuilder();
        quote(sb, s);
        return sb.toString();
    }
}
