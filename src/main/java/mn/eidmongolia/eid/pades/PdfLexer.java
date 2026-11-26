package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import mn.eidmongolia.eid.internal.Text;

/** PDF object lexer/parser (ISO 32000-1 §7.3) — the digitorus/pdf subset the Go writer uses. */
final class PdfLexer {
    final byte[] b;
    int pos;

    PdfLexer(byte[] b) {
        this(b, 0);
    }

    PdfLexer(byte[] b, int pos) {
        this.b = b;
        this.pos = pos;
    }

    static boolean isWhite(int c) {
        return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    static boolean isDelim(int c) {
        return c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B || c == 0x5D || c == 0x7B || c == 0x7D || c == 0x2F
            || c == 0x25;
    }

    static boolean isRegular(int c) {
        return !isWhite(c) && !isDelim(c);
    }

    static Long toLong(String w) {
        if (w == null) return null;
        try {
            return Long.parseLong(w);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Integer toInt(String w) {
        if (w == null) return null;
        try {
            return Integer.parseInt(w);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    static Double real(String w) {
        if (w.indexOf('.') < 0) return null;
        for (int i = 0; i < w.length(); i++) {
            char c = w.charAt(i);
            if (!(c >= '0' && c <= '9') && c != '.' && c != '-' && c != '+') return null;
        }
        String s = w;
        if (s.startsWith(".") || s.startsWith("-.") || s.startsWith("+.")) s = s.replace(".", "0.");
        try {
            return Double.parseDouble(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private int at(int i) {
        return b[i] & 0xff;
    }

    void skipWhite() {
        while (pos < b.length) {
            int c = at(pos);
            if (isWhite(c)) {
                pos++;
                continue;
            }
            if (c == 0x25) {
                while (pos < b.length && at(pos) != 10 && at(pos) != 13) pos++;
                continue;
            }
            break;
        }
    }

    /** The regular word starting at or after [p] (white space skipped) and its end, or null. */
    Object[] peekWord(int p) {
        int i = p;
        while (i < b.length && isWhite(at(i))) i++;
        int s = i;
        while (i < b.length && isRegular(at(i))) i++;
        if (i <= s) return null;
        return new Object[] {new String(b, s, i - s, StandardCharsets.ISO_8859_1), i};
    }

    String word() {
        skipWhite();
        Object[] w = peekWord(pos);
        if (w == null) return null;
        pos = (Integer) w[1];
        return (String) w[0];
    }

    void expect(String keyword) {
        if (!keyword.equals(word())) throw new PdfException("expected " + keyword + " at " + pos);
    }

    PdfObj parseObject() {
        return parseObject(0);
    }

    PdfObj parseObject(int depth) {
        if (depth >= 64) throw new PdfException("nesting too deep");
        skipWhite();
        if (pos >= b.length) throw new PdfException("unexpected end of file");
        switch (at(pos)) {
            case 0x2F: {
                pos++;
                StringBuilder sb = new StringBuilder();
                while (pos < b.length && isRegular(at(pos))) {
                    int ch = at(pos);
                    if (ch == 0x23 && pos + 2 < b.length) {
                        int hi = Text.hexVal(at(pos + 1));
                        int lo = Text.hexVal(at(pos + 2));
                        if (hi >= 0 && lo >= 0) {
                            ch = (hi << 4) | lo;
                            pos += 2;
                        }
                    }
                    sb.append((char) ch);
                    pos++;
                }
                return new PdfObj.Name(sb.toString());
            }
            case 0x28:
                return new PdfObj.Str(literalString());
            case 0x3C: {
                if (pos + 1 < b.length && at(pos + 1) == 0x3C) {
                    pos += 2;
                    PdfDict d = new PdfDict();
                    while (true) {
                        skipWhite();
                        if (pos >= b.length) throw new PdfException("unterminated dictionary");
                        if (at(pos) == 0x3E && pos + 1 < b.length && at(pos + 1) == 0x3E) {
                            pos += 2;
                            break;
                        }
                        PdfObj key = parseObject(depth + 1);
                        if (!(key instanceof PdfObj.Name)) throw new PdfException("dictionary key is not a name at " + pos);
                        PdfObj value = parseObject(depth + 1);
                        // null value = absent key (§7.3.7); the last duplicate wins (Go map, [Structure]), so a later null
                        // removes an earlier value — `/Filter /FlateDecode /Filter null` is unfiltered for both.
                        if (value.isNull()) d.entries.remove(((PdfObj.Name) key).v());
                        else d.entries.put(((PdfObj.Name) key).v(), value);
                    }
                    return new PdfObj.Dict(d);
                }
                return new PdfObj.Str(hexString());
            }
            case 0x5B: {
                pos++;
                List<PdfObj> a = new ArrayList<>();
                while (true) {
                    skipWhite();
                    if (pos >= b.length) throw new PdfException("unterminated array");
                    if (at(pos) == 0x5D) {
                        pos++;
                        break;
                    }
                    a.add(parseObject(depth + 1));
                }
                return new PdfObj.Arr(a);
            }
            default:
                break;
        }
        int c = at(pos);
        String w = word();
        if (w == null) throw new PdfException("unexpected byte " + c + " at " + pos);
        switch (w) {
            case "true":
                return new PdfObj.Bool(true);
            case "false":
                return new PdfObj.Bool(false);
            case "null":
                return PdfObj.NULL;
            default:
                break;
        }
        Long i = toLong(w);
        if (i != null) {
            int save = pos;
            if (i >= 0) {
                Object[] g = peekWord(pos);
                Integer gen = g == null ? null : toInt((String) g[0]);
                if (g != null && gen != null && gen >= 0) {
                    Object[] r = peekWord((Integer) g[1]);
                    if (r != null && r[0].equals("R")) {
                        pos = (Integer) r[1];
                        return new PdfObj.Ref(new PdfRef((int) (long) i, gen));
                    }
                }
            }
            pos = save;
            return new PdfObj.Int(i);
        }
        Double r = real(w);
        if (r != null) return new PdfObj.Real(r);
        throw new PdfException("unexpected token " + w + " at " + pos);
    }

    private byte[] hexString() {
        pos++;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int hi = -1;
        while (pos < b.length) {
            int c = at(pos++);
            if (c == 0x3E) {
                if (hi >= 0) out.write(hi << 4);
                return out.toByteArray();
            }
            if (isWhite(c)) continue;
            int v = Text.hexVal(c);
            if (v < 0) throw new PdfException("bad hex string");
            if (hi >= 0) {
                out.write((hi << 4) | v);
                hi = -1;
            } else {
                hi = v;
            }
        }
        throw new PdfException("unterminated hex string");
    }

    private byte[] literalString() {
        pos++;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int depth = 1;
        while (pos < b.length) {
            int c = at(pos++);
            switch (c) {
                case 0x5C: {
                    if (pos >= b.length) continue;
                    int e = at(pos++);
                    switch (e) {
                        case 0x6E: out.write(10); break;
                        case 0x72: out.write(13); break;
                        case 0x74: out.write(9); break;
                        case 0x62: out.write(8); break;
                        case 0x66: out.write(12); break;
                        case 0x0D:
                            if (pos < b.length && at(pos) == 0x0A) pos++;
                            break;
                        case 0x0A:
                            break;
                        default:
                            if (e >= 0x30 && e <= 0x37) {
                                int v = e - 0x30;
                                int k = 0;
                                while (k < 2 && pos < b.length && at(pos) >= 0x30 && at(pos) <= 0x37) {
                                    v = v * 8 + (at(pos) - 0x30);
                                    pos++;
                                    k++;
                                }
                                out.write(v & 0xff);
                            } else {
                                out.write(e);
                            }
                    }
                    break;
                }
                case 0x28:
                    depth++;
                    out.write(c);
                    break;
                case 0x29:
                    depth--;
                    if (depth == 0) return out.toByteArray();
                    out.write(c);
                    break;
                case 0x0D:
                    if (pos < b.length && at(pos) == 0x0A) pos++;
                    out.write(0x0A);
                    break;
                default:
                    out.write(c);
            }
        }
        throw new PdfException("unterminated literal string");
    }
}
