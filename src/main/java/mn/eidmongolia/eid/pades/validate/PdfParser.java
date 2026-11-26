package mn.eidmongolia.eid.pades.validate;

import static mn.eidmongolia.eid.pades.validate.PdfObjects.MAX_OBJECT_NUMBER;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.MAX_PDF_DEPTH;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.dget;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isDict;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isDigit;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isGapSpace;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isInt;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isPDFDelim;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isPDFSpace;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isRef;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.pdfEqual;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PName;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PReal;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PRef;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStr;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStream;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PdfBudget;

/** TS pdfobj.ts PdfParser: a strict PDF object parser over b[0, len). */
final class PdfParser {
    private static final Pattern INT_RE = Pattern.compile("[+-]?[0-9]+");
    private static final Pattern FLOAT_RE = Pattern.compile("[+-]?([0-9]+\\.[0-9]*|\\.[0-9]+)");

    /** A parsed "n g obj ... endobj" (TS Indirect). */
    static final class Indirect {
        final int num;
        final int gen;
        Object val;

        Indirect(int num, int gen) {
            this.num = num;
            this.gen = gen;
        }
    }

    final byte[] b;
    final int len;
    int pos;
    final PdfBudget budget;
    boolean strict;

    PdfParser(byte[] b, int len, int pos, PdfBudget budget) {
        this(b, len, pos, budget, false);
    }

    PdfParser(byte[] b, int len, int pos, PdfBudget budget, boolean strict) {
        this.b = b;
        this.len = len;
        this.pos = pos;
        this.budget = budget;
        this.strict = strict;
    }

    private int at(int i) {
        return b[i] & 0xff;
    }

    void skipGap() {
        while (pos < len && isGapSpace(at(pos))) pos++;
    }

    void skipSpace() {
        if (strict) {
            skipGap();
            return;
        }
        while (pos < len && isPDFSpace(at(pos))) pos++;
    }

    /** Whitespace and comments; strict mode: isGapSpace only. */
    void skip() {
        if (strict) {
            skipGap();
            return;
        }
        while (pos < len) {
            int c = at(pos);
            if (isPDFSpace(c)) pos++;
            else if (c == '%') {
                while (pos < len && at(pos) != 10 && at(pos) != 13) pos++;
            } else return;
        }
    }

    boolean keyword(String k) {
        int e = pos + k.length();
        if (e > len) return false;
        for (int i = 0; i < k.length(); i++) if (at(pos + i) != k.charAt(i)) return false;
        if (e < len && !isPDFSpace(at(e)) && !isPDFDelim(at(e))) return false;
        pos = e;
        return true;
    }

    /** Go uint(): at most 18 digits; -1 when absent. */
    long uint() {
        int s = pos;
        while (pos < len && isDigit(at(pos))) pos++;
        if (pos == s || pos - s > 18) {
            pos = s;
            return -1;
        }
        return Long.parseLong(PdfObjects.latin1(b, s, pos));
    }

    Object value(int depth) {
        if (depth > MAX_PDF_DEPTH) throw PdfObjError.syntax();
        budget.node();
        skip();
        if (pos >= len) throw PdfObjError.syntax();
        int c = at(pos);
        if (c == '/') {
            pos++;
            return name();
        }
        if (c == '(') {
            pos++;
            return literal();
        }
        if (c == '[') {
            pos++;
            List<Object> arr = new ArrayList<>();
            for (;;) {
                skip();
                if (pos < len && at(pos) == ']') {
                    pos++;
                    return arr;
                }
                arr.add(value(depth + 1));
            }
        }
        if (c == '<') {
            if (pos + 1 < len && at(pos + 1) == '<') {
                pos += 2;
                return dict(depth);
            }
            pos++;
            return hex();
        }
        if (isDigit(c) || c == '+' || c == '-' || c == '.') return number();
        if (keyword("true")) return Boolean.TRUE;
        if (keyword("false")) return Boolean.FALSE;
        if (keyword("null")) return null;
        throw PdfObjError.syntax();
    }

    Map<String, Object> dict(int depth) {
        Map<String, Object> d = new LinkedHashMap<>();
        for (;;) {
            skip();
            if (pos + 1 < len && at(pos) == '>' && at(pos + 1) == '>') {
                pos += 2;
                for (Iterator<Object> it = d.values().iterator(); it.hasNext();) if (it.next() == null) it.remove();
                return d;
            }
            if (pos >= len || at(pos) != '/') throw PdfObjError.syntax();
            pos++;
            String key = name().v;
            boolean dup = d.containsKey(key);
            Object old = d.get(key);
            Object v = value(depth + 1);
            if (dup && !pdfEqual(old, v)) throw PdfObjError.syntax();
            d.put(key, v);
        }
    }

    private static int hex2(int hi, int lo) {
        int h = Character.digit(hi, 16);
        int l = Character.digit(lo, 16);
        // Character.digit accepts non-ASCII digits; restrict to [0-9a-fA-F] like TS HEX2.
        if (h < 0 || l < 0 || hi > 'f' || lo > 'f') return -1;
        return (h << 4) | l;
    }

    PName name() {
        StringBuilder out = new StringBuilder();
        while (pos < len && !isPDFSpace(at(pos)) && !isPDFDelim(at(pos))) {
            int c = at(pos);
            if (c == '#') {
                if (pos + 2 >= len) throw PdfObjError.syntax();
                int x = hex2(at(pos + 1), at(pos + 2));
                if (x < 0) throw PdfObjError.syntax();
                c = x;
                pos += 2;
            }
            out.append((char) c);
            pos++;
        }
        return new PName(out.toString());
    }

    PStr literal() {
        StringBuilder out = new StringBuilder();
        for (int depth = 1;; pos++) {
            if (pos >= len) throw PdfObjError.syntax();
            int c = at(pos);
            if (c == '(') depth++;
            else if (c == ')') {
                if (--depth == 0) {
                    pos++;
                    return new PStr(out.toString());
                }
            } else if (c == 0x0d) {
                if (pos + 1 < len && at(pos + 1) == 0x0a) pos++;
                c = 0x0a;
            } else if (c == '\\') {
                if (++pos >= len) throw PdfObjError.syntax();
                int e = at(pos);
                if (e == 'n') c = 0x0a;
                else if (e == 'r') c = 0x0d;
                else if (e == 't') c = 0x09;
                else if (e == 'b') c = 0x08;
                else if (e == 'f') c = 0x0c;
                else if (e == 0x0a) continue;
                else if (e == 0x0d) {
                    if (pos + 1 < len && at(pos + 1) == 0x0a) pos++;
                    continue;
                } else if (e >= '0' && e <= '7') {
                    c = 0;
                    for (int i = 0; i < 3 && pos < len && at(pos) >= '0' && at(pos) <= '7'; i++) {
                        c = ((c << 3) | (at(pos) - '0')) & 0xff;
                        pos++;
                    }
                    pos--;
                } else c = e;
            }
            out.append((char) c);
        }
    }

    PStr hex() {
        StringBuilder digits = new StringBuilder();
        for (;; pos++) {
            if (pos >= len) throw PdfObjError.syntax();
            int c = at(pos);
            if (c == '>') {
                pos++;
                break;
            }
            if (!isPDFSpace(c)) digits.append((char) c);
        }
        if (digits.length() % 2 == 1) digits.append('0');
        StringBuilder out = new StringBuilder(digits.length() / 2);
        for (int i = 0; i < digits.length(); i += 2) {
            int x = hex2(digits.charAt(i), digits.charAt(i + 1));
            if (x < 0) throw PdfObjError.syntax();
            out.append((char) x);
        }
        return new PStr(out.toString());
    }

    /** Integer / real, or an "n g R" reference. */
    Object number() {
        int s = pos;
        while (pos < len && "0123456789+-.".indexOf(at(pos)) >= 0) pos++;
        String tok = PdfObjects.latin1(b, s, pos);
        if (pos < len && !isPDFSpace(at(pos)) && !isPDFDelim(at(pos))) throw PdfObjError.syntax();
        if (tok.indexOf('.') >= 0) {
            if (!FLOAT_RE.matcher(tok).matches()) throw PdfObjError.syntax();
            double f = Double.parseDouble(tok);
            if (Double.isInfinite(f) || Double.isNaN(f)) throw PdfObjError.syntax();
            return new PReal(f);
        }
        if (!INT_RE.matcher(tok).matches()) throw PdfObjError.syntax();
        long n;
        try {
            n = Long.parseLong(tok);
        } catch (NumberFormatException e) {
            throw PdfObjError.syntax(); // outside int64
        }
        if (n >= 0 && tok.charAt(0) != '+') {
            int save = pos;
            skip();
            long g = uint();
            if (g >= 0) {
                skip();
                if (keyword("R")) {
                    if (n >= MAX_OBJECT_NUMBER || g > 65535) throw PdfObjError.syntax();
                    return new PRef((int) n, (int) g);
                }
            }
            pos = save;
        }
        return n;
    }

    /** "n g obj ... endobj". length resolves an indirect /Length in its view (null: an error). */
    Indirect indirect(Function<PRef, Long> length) {
        skipSpace();
        long n = uint();
        skipSpace();
        long g = uint();
        skipSpace();
        if (n < 0 || g < 0 || n >= MAX_OBJECT_NUMBER || g > 65535 || !keyword("obj")) throw PdfObjError.syntax();
        Indirect o = new Indirect((int) n, (int) g);
        o.val = value(0);
        skip();
        if (isDict(o.val) && keyword("stream")) {
            Map<String, Object> d = PdfObjects.dict(o.val);
            if (pos < len && at(pos) == 0x0d) pos++;
            if (pos >= len || at(pos) != 0x0a) throw PdfObjError.syntax();
            pos++;
            long size;
            Object l = dget(d, "Length");
            if (isInt(l)) size = (Long) l;
            else if (isRef(l)) {
                if (length == null) throw PdfObjError.syntax();
                size = length.apply((PRef) l);
            } else throw PdfObjError.syntax();
            if (size < 0 || size > len - pos) throw PdfObjError.syntax();
            int sz = (int) size;
            budget.copy(sz);
            o.val = new PStream(d, Arrays.copyOfRange(b, pos, pos + sz));
            pos += sz;
            skipSpace();
            if (!keyword("endstream")) throw PdfObjError.syntax();
            skip();
        }
        if (!keyword("endobj")) throw PdfObjError.syntax();
        return o;
    }

    /** "startxref N %%EOF"; N, or -1. */
    long startxref() {
        skipGap();
        if (!keyword("startxref")) return -1;
        skipGap();
        long n = uint();
        skipGap();
        if (n < 0 || n > len || !PdfObjects.latin1(b, pos, Math.min(len, pos + 5)).equals("%%EOF")) return -1;
        pos += 5;
        return n;
    }
}
