package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import mn.eidmongolia.eid.internal.Text;

/**
 * Occupancy scanner — PLACEMENT_SPEC.md §3–§5, 1:1 port of the Go reference `pades/internal/core/occupancy.go`. A pure
 * function of the page objects. Any failure (limit, unsupported filter, broken stream, unparsable object) is
 * [Unscannable] (or a reader exception) — the stamp then stays where it was requested.
 *
 * Arithmetic (§2): IEEE-754 binary64, `+ − × ÷` only, each product rounded on its own and the terms summed left to right
 * as written. JVM double arithmetic is strict (no FMA contraction); `Math.fma` is never used.
 */
final class Occupancy {
    static final class Unscannable extends RuntimeException {
        Unscannable(String msg) {
            super(msg);
        }
    }

    // Limits (§5).
    static final int MAX_BYTES = 4 << 20;      // decoded content bytes, page + every form execution
    static final int MAX_OPS = 100_000;        // operators executed, page + forms
    static final int MAX_DEPTH = 8;            // form XObject nesting (page content = 0)
    static final int MAX_SAVE = 64;            // q nesting per content stream
    static final int MAX_OPERANDS = 65_536;    // operand objects pending at one operator
    static final int MAX_NESTING = 32;         // array / dictionary nesting in an operand
    static final int MAX_ANNOTS = 10_000;      // /Annots entries
    static final int MAX_W_ENTRIES = 65_536;   // CIDFont /W: elements read
    static final int MAX_W_ASSIGN = 262_144;   // CIDFont /W: CID assignments attempted before reading stops
    static final int MAX_NUM_LEN = 32;         // a longer numeric token is not a number
    static final double CLAMP = 1e7;           // box coordinates are clamped to ±CLAMP pt before quantising

    private Occupancy() {
    }

    /** Occupied boxes of a page in default user space, h100, outward-rounded, in emission order. */
    static List<long[]> scan(PdfReader rd, PdfDict page, int pageId, long[] box) {
        Scanner s = new Scanner(rd, box);
        Val pg = new Val(new PdfObj.Dict(page), pageId);
        byte[] content = s.pageContent(s.key(pg, "Contents"));
        Val res = s.inherited(pg, "Resources");
        s.run(content, res, new GState(), 0);
        s.annots(s.key(pg, "Annots"));
        return s.boxes;
    }

    // ── Values (digitorus/pdf `Value` semantics) ──

    /** A resolved object and the id of the indirect object it lives in (the font cache key). */
    static final class Val {
        static final Val NULL = new Val(PdfObj.NULL, 0);
        final PdfObj o;
        final int ptr;

        Val(PdfObj o, int ptr) {
            this.o = o;
            this.ptr = ptr;
        }

        boolean isNull() {
            return o.isNull();
        }

        String name() {
            String n = o.name();
            return n == null ? "" : n;
        }

        int count() {
            List<PdfObj> a = o.array();
            return a == null ? 0 : a.size();
        }

        boolean isDict() {
            return o instanceof PdfObj.Dict;
        }

        boolean isStream() {
            return o instanceof PdfObj.Stream;
        }

        boolean isArray() {
            return o instanceof PdfObj.Arr;
        }

        /** Integer or real. */
        Double number() {
            if (o instanceof PdfObj.Int) return (double) ((PdfObj.Int) o).v();
            if (o instanceof PdfObj.Real) return ((PdfObj.Real) o).v();
            return null;
        }
    }

    // ── Arithmetic (§2) ──

    static final double[] IDENTITY = {1.0, 0.0, 0.0, 1.0, 0.0, 0.0};

    /** m × n (row-vector convention), each product rounded on its own, summed left to right. Never mutated in place. */
    static double[] mul(double[] m, double[] n) {
        return new double[] {
            m[0] * n[0] + m[1] * n[2],
            m[0] * n[1] + m[1] * n[3],
            m[2] * n[0] + m[3] * n[2],
            m[2] * n[1] + m[3] * n[3],
            m[4] * n[0] + m[5] * n[2] + n[4],
            m[4] * n[1] + m[5] * n[3] + n[5],
        };
    }

    /** (x, y) × m = (a·x + c·y + e, b·x + d·y + f). */
    static double[] apply(double[] m, double x, double y) {
        return new double[] {m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]};
    }

    static boolean finite(double[] m) {
        for (double v : m) if (!Double.isFinite(v)) return false;
        return true;
    }

    /** Go `int(f)`: truncation toward zero; saturating, NaN → 0 (Java's (long) cast). */
    static long toLong(double v) {
        return (long) v;
    }

    /** A float bounding box being accumulated (Math.min/max = Go min/max: NaN wins, −0 < +0). */
    static final class Rect {
        double x0;
        double y0;
        double x1;
        double y1;

        Rect(double x0, double y0, double x1, double y1) {
            this.x0 = x0;
            this.y0 = y0;
            this.x1 = x1;
            this.y1 = y1;
        }

        Rect(double x, double y) {
            this(x, y, x, y);
        }

        void add(double x, double y) {
            x0 = Math.min(x0, x);
            y0 = Math.min(y0, y);
            x1 = Math.max(x1, x);
            y1 = Math.max(y1, y);
        }
    }

    /** Outward to h100 after clamping to ±CLAMP pt: floor(min·100), ceil(max·100). NaN → unscannable. */
    static long[] quantise(Rect r) {
        double[] v = {r.x0, r.y0, r.x1, r.y1};
        for (int i = 0; i < 4; i++) {
            if (Double.isNaN(v[i])) throw new Unscannable("NaN");
            v[i] = Math.min(Math.max(v[i], -CLAMP), CLAMP);
        }
        return new long[] {(long) Math.floor(v[0] * 100), (long) Math.floor(v[1] * 100), (long) Math.ceil(v[2] * 100), (long) Math.ceil(v[3] * 100)};
    }

    // ── Fonts (§3.4) ──

    enum FontKind { SIMPLE, IDENTITY, COMPOSITE, FALLBACK }

    interface GlyphFn {
        void glyph(double w0, boolean space);
    }

    static final class Font {
        static final Font FALLBACK = new Font(FontKind.FALLBACK);
        final FontKind kind;
        long first;
        final List<Double> widths = new ArrayList<>();
        double missing = 1000.0;
        double dw = 1000.0;
        final Map<Long, Double> w = new HashMap<>();

        Font(FontKind kind) {
            this.kind = kind;
        }

        /** Each code's width (glyph space, 1/1000 em) and whether it is the 1-byte code 32 (word spacing). */
        void glyphs(byte[] b, GlyphFn fn) {
            if (kind == FontKind.IDENTITY) {
                for (int i = 0; i + 1 < b.length; i += 2) {
                    long cid = ((b[i] & 0xffL) << 8) | (b[i + 1] & 0xffL);
                    Double v = w.get(cid);
                    fn.glyph(v != null ? v : dw, false);
                }
                return;
            }
            for (byte cb : b) {
                int c = cb & 0xff;
                double w0 = 1000.0;
                if (kind == FontKind.SIMPLE) {
                    w0 = missing;
                    long i = c - first;
                    if (i >= 0 && i < widths.size()) {
                        Double v = widths.get((int) i);
                        if (v != null) w0 = v;
                    }
                }
                fn.glyph(w0, kind != FontKind.COMPOSITE && c == 0x20);
            }
        }
    }

    // ── Content lexer (§3.1) ──

    /** Operand kinds: Num, Str, Name, Arr; DICT and OTHER are singletons. */
    static class Operand {
        static final Operand DICT = new Operand();
        /** true/false/null, or a keyword inside an array/dictionary. */
        static final Operand OTHER = new Operand();
    }

    static final class Num extends Operand {
        final double v;

        Num(double v) {
            this.v = v;
        }
    }

    static final class Str extends Operand {
        final byte[] b;

        Str(byte[] b) {
            this.b = b;
        }
    }

    static final class Name extends Operand {
        final String v;

        Name(String v) {
            this.v = v;
        }
    }

    static final class Arr extends Operand {
        final List<Operand> items;

        Arr(List<Operand> items) {
            this.items = items;
        }
    }

    /** kind: EOF, OBJ (operand [o], container [open] "[" | "<<" | ""), KEYWORD ([kw]), ARR_END, DICT_END. */
    static final class Token {
        static final int EOF = 0;
        static final int OBJ = 1;
        static final int KEYWORD = 2;
        static final int ARR_END = 3;
        static final int DICT_END = 4;
        static final Token T_EOF = new Token(EOF, null, "", null);
        static final Token T_ARR_END = new Token(ARR_END, null, "", null);
        static final Token T_DICT_END = new Token(DICT_END, null, "", null);

        final int kind;
        final Operand o;
        final String open;
        final String kw;

        Token(int kind, Operand o, String open, String kw) {
            this.kind = kind;
            this.o = o;
            this.open = open;
            this.kw = kw;
        }

        static Token obj(Operand o, String open) {
            return new Token(OBJ, o, open, null);
        }
    }

    static final class Lexer {
        final byte[] b;
        int i;

        Lexer(byte[] b) {
            this.b = b;
        }

        private int at(int p) {
            return b[p] & 0xff;
        }

        static boolean isSpace(int c) {
            return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
        }

        static boolean isDelim(int c) {
            switch (c) {
                case 0x28: case 0x29: case 0x3C: case 0x3E: case 0x5B: case 0x5D: case 0x7B: case 0x7D: case 0x2F: case 0x25:
                    return true;
                default:
                    return false;
            }
        }

        /** [+-]?(\d+(\.\d*)?|\.\d+), at most MAX_NUM_LEN bytes. */
        static boolean isNumber(byte[] t) {
            if (t.length == 0 || t.length > MAX_NUM_LEN) return false;
            int i = 0;
            if (t[0] == '+' || t[0] == '-') i++;
            int digits = 0;
            boolean dot = false;
            for (; i < t.length; i++) {
                int c = t[i] & 0xff;
                if (c >= 0x30 && c <= 0x39) digits++;
                else if (c == 0x2E && !dot) dot = true;
                else return false;
            }
            return digits > 0;
        }

        void skipSpace() {
            while (i < b.length) {
                int c = at(i);
                if (isSpace(c)) {
                    i++;
                } else if (c == 0x25) {
                    while (i < b.length && at(i) != 0x0D && at(i) != 0x0A) i++;
                } else {
                    return;
                }
            }
        }

        byte[] regular() {
            int s = i;
            while (i < b.length && !isSpace(at(i)) && !isDelim(at(i))) i++;
            return Arrays.copyOfRange(b, s, i);
        }

        /** After '(' : balanced parentheses, escapes; EOF ends the string. */
        byte[] literal() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int depth = 1;
            while (i < b.length) {
                int c = at(i);
                i++;
                if (c == 0x28) {
                    depth++;
                } else if (c == 0x29) {
                    depth--;
                    if (depth == 0) return out.toByteArray();
                } else if (c == 0x5C) {
                    if (i >= b.length) return out.toByteArray();
                    int e = at(i);
                    i++;
                    switch (e) {
                        case 0x6E: c = 0x0A; break;
                        case 0x72: c = 0x0D; break;
                        case 0x74: c = 0x09; break;
                        case 0x62: c = 0x08; break;
                        case 0x66: c = 0x0C; break;
                        case 0x0D:
                            if (i < b.length && at(i) == 0x0A) i++;
                            continue;
                        case 0x0A:
                            continue;
                        default:
                            if (e >= 0x30 && e <= 0x37) {
                                int v = e - 0x30;
                                int k = 0;
                                while (k < 2 && i < b.length && at(i) >= 0x30 && at(i) <= 0x37) {
                                    v = v * 8 + (at(i) - 0x30);
                                    i++;
                                    k++;
                                }
                                c = v & 0xff;
                            } else {
                                c = e;
                            }
                    }
                }
                out.write(c);
            }
            return out.toByteArray();
        }

        /** After '<' : hex digits, other bytes skipped, odd final nibble padded with 0; '>' or EOF ends it. */
        byte[] hexString() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int hi = 0;
            boolean half = false;
            while (i < b.length) {
                int c = at(i);
                i++;
                if (c == 0x3E) break;
                int v = Text.hexVal(c);
                if (v < 0) continue;
                if (half) out.write((hi << 4) | v);
                else hi = v;
                half = !half;
            }
            if (half) out.write(hi << 4);
            return out.toByteArray();
        }

        /** After '/' : regular bytes, #xx decoded (one char per byte, as PdfObj names). */
        String name() {
            byte[] t = regular();
            StringBuilder sb = new StringBuilder();
            int k = 0;
            while (k < t.length) {
                int c = t[k] & 0xff;
                if (c == 0x23 && k + 2 < t.length) {
                    int h = Text.hexVal(t[k + 1] & 0xff);
                    int lo = Text.hexVal(t[k + 2] & 0xff);
                    if (h >= 0 && lo >= 0) {
                        sb.append((char) ((h << 4) | lo));
                        k += 3;
                        continue;
                    }
                }
                sb.append((char) c);
                k++;
            }
            return sb.toString();
        }

        /** One token; '{' '}' and stray ')' / '>' are skipped. */
        Token next() {
            while (true) {
                skipSpace();
                if (i >= b.length) return Token.T_EOF;
                switch (at(i)) {
                    case 0x28:
                        i++;
                        return Token.obj(new Str(literal()), "");
                    case 0x3C:
                        if (i + 1 < b.length && at(i + 1) == 0x3C) {
                            i += 2;
                            return Token.obj(Operand.DICT, "<<");
                        }
                        i++;
                        return Token.obj(new Str(hexString()), "");
                    case 0x3E:
                        if (i + 1 < b.length && at(i + 1) == 0x3E) {
                            i += 2;
                            return Token.T_DICT_END;
                        }
                        i++;
                        continue;
                    case 0x5B:
                        i++;
                        return Token.obj(new Arr(Collections.emptyList()), "[");
                    case 0x5D:
                        i++;
                        return Token.T_ARR_END;
                    case 0x2F:
                        i++;
                        return Token.obj(new Name(name()), "");
                    case 0x29:
                    case 0x7B:
                    case 0x7D:
                        i++;
                        continue;
                    default:
                        break;
                }
                byte[] t = regular();
                String s = new String(t, StandardCharsets.ISO_8859_1);
                if (isNumber(t)) {
                    try {
                        return Token.obj(new Num(Double.parseDouble(s)), "");
                    } catch (NumberFormatException e) {
                        return Token.obj(Operand.OTHER, "");
                    }
                }
                if (s.equals("true") || s.equals("false") || s.equals("null")) return Token.obj(Operand.OTHER, "");
                return new Token(Token.KEYWORD, null, "", s);
            }
        }

        /** Result of [obj]: the completed operand and whether EOF ended the content. */
        static final class Completed {
            final Operand o;
            final boolean eof;

            Completed(Operand o, boolean eof) {
                this.o = o;
                this.eof = eof;
            }
        }

        /**
         * Completes an array or dictionary opened by [next] (open = "[" or "<<"). Inside, every token is an element; EOF
         * ends the content (eof = true). Nesting > MAX_NESTING or too many elements → unscannable.
         */
        Completed obj(Operand o, String open, int depth, int[] count) {
            if (open.isEmpty()) return new Completed(o, false);
            if (depth >= MAX_NESTING) throw new Unscannable("nesting");
            List<Operand> elems = new ArrayList<>();
            boolean arr = open.equals("[");
            while (true) {
                Token t = next();
                Operand e;
                if (t.kind == Token.EOF) return new Completed(arr ? new Arr(elems) : o, true);
                if (t.kind == Token.ARR_END) {
                    if (arr) return new Completed(new Arr(elems), false);
                    continue;
                }
                if (t.kind == Token.DICT_END) {
                    if (!arr) return new Completed(o, false);
                    continue;
                }
                if (t.kind == Token.KEYWORD) {
                    e = Operand.OTHER;
                } else {
                    Completed y = obj(t.o, t.open, depth + 1, count);
                    if (y.eof) return new Completed(arr ? new Arr(elems) : o, true);
                    e = y.o;
                }
                count[0]++;
                if (count[0] > MAX_OPERANDS) throw new Unscannable("operands");
                if (arr) elems.add(e);
            }
        }
    }

    // ── Interpreter (§3.2–§3.6) ──

    /** Graphics + text state; saved by `q` as a copy (arrays are never mutated in place). */
    static final class GState {
        double[] ctm = IDENTITY;
        double lw = 1.0;
        boolean fillWhite;
        boolean strokeWhite;
        double tc;
        double tw;
        double th = 1.0;
        double tl;
        double tfs;
        double trise;
        Font font = Font.FALLBACK;

        GState copy() {
            GState g = new GState();
            g.ctm = ctm;
            g.lw = lw;
            g.fillWhite = fillWhite;
            g.strokeWhite = strokeWhite;
            g.tc = tc;
            g.tw = tw;
            g.th = th;
            g.tl = tl;
            g.tfs = tfs;
            g.trise = trise;
            g.font = font;
            return g;
        }
    }

    static final class Subpath {
        final double sx;
        final double sy;
        double cx;
        double cy;
        final Rect bbox;
        final List<Rect> segs = new ArrayList<>();

        Subpath(double sx, double sy) {
            this.sx = sx;
            this.sy = sy;
            cx = sx;
            cy = sy;
            bbox = new Rect(sx, sy);
        }

        void close() {
            Rect seg = new Rect(cx, cy);
            seg.add(sx, sy);
            segs.add(seg);
            cx = sx;
            cy = sy;
        }
    }

    static final class Scanner {
        private final PdfReader rd;
        private final long[] page;
        private int bytes;
        private int ops;
        final List<long[]> boxes = new ArrayList<>();
        private final Map<Integer, Font> fonts = new HashMap<>();

        Scanner(PdfReader rd, long[] page) {
            this.rd = rd;
            this.page = page;
        }

        // digitorus resolve: a reference becomes the object it names (ptr = its id); a missing object is null; a
        // reference to a reference is a reader failure.
        private Val res(PdfObj x, int parent) {
            if (!(x instanceof PdfObj.Ref)) return new Val(x, parent);
            PdfRef r = ((PdfObj.Ref) x).r();
            PdfObj y = rd.obj(r);
            if (y instanceof PdfObj.Ref) throw new Unscannable("reference to a reference");
            if (y.isNull()) return Val.NULL;
            return new Val(y, r.id());
        }

        Val key(Val v, String k) {
            PdfDict d = v.o.dict();
            if (d == null) return Val.NULL;
            return res(d.get(k), v.ptr);
        }

        Val index(Val v, int i) {
            List<PdfObj> a = v.o.array();
            if (a == null || i < 0 || i >= a.size()) return Val.NULL;
            return res(a.get(i), v.ptr);
        }

        /** A page attribute, following /Parent (depth ≤ 32). */
        Val inherited(Val page, String k) {
            Val v = page;
            for (int n = 0; n < 32; n++) {
                Val x = key(v, k);
                if (!x.isNull()) return x;
                v = key(v, "Parent");
                if (!v.isDict()) return Val.NULL;
            }
            return Val.NULL;
        }

        private void emit(Rect r) {
            boxes.add(quantise(r));
        }

        private static boolean isFlateName(Val v) {
            return v.o instanceof PdfObj.Name && v.name().equals("FlateDecode");
        }

        /** Decoded bytes of a content/form stream: no filter, or exactly FlateDecode without parameters (§3.1). */
        byte[] stream(Val v) {
            if (!(v.o instanceof PdfObj.Stream)) throw new Unscannable("not a stream");
            PdfObj.Stream s = (PdfObj.Stream) v.o;
            Val f = key(v, "Filter");
            Val p = key(v, "DecodeParms");
            boolean flate;
            if (f.isNull() && p.isNull()) {
                flate = false;
            } else if (isFlateName(f) && p.isNull()) {
                flate = true;
            } else if (f.isArray() && f.count() == 1 && isFlateName(index(f, 0)) && (p.isNull() || (p.isArray() && p.count() == 1 && index(p, 0).isNull()))) {
                flate = true;
            } else {
                throw new Unscannable("filter");
            }
            if (s.start() < 0 || s.end() > rd.bytes.length || s.start() > s.end()) throw new Unscannable("stream range");
            byte[] raw = Arrays.copyOfRange(rd.bytes, s.start(), s.end());
            int left = MAX_BYTES - bytes;
            byte[] out = flate ? inflate(raw, left) : raw;
            if (out.length > left) throw new Unscannable("content bytes");
            bytes += out.length;
            return out;
        }

        /** /Contents: absent → empty; a stream; or an array of streams joined with LF. */
        byte[] pageContent(Val c) {
            if (c.o.isNull()) return new byte[0];
            if (c.o instanceof PdfObj.Stream) return stream(c);
            if (c.o instanceof PdfObj.Arr) {
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                for (int i = 0; i < c.count(); i++) {
                    byte[] b = stream(index(c, i));
                    if (i > 0) out.write(0x0A);
                    out.write(b, 0, b.length);
                }
                return out.toByteArray();
            }
            throw new Unscannable("/Contents");
        }

        private Font font(Val v) {
            if (!v.isDict()) return Font.FALLBACK;
            if (v.ptr != 0) {
                Font hit = fonts.get(v.ptr);
                if (hit != null) return hit;
            }
            Font f = loadFont(v);
            if (v.ptr != 0) fonts.put(v.ptr, f);
            return f;
        }

        private Font loadFont(Val v) {
            String subtype = key(v, "Subtype").name();
            if (subtype.equals("Type3")) return Font.FALLBACK;
            if (subtype.equals("Type0")) {
                Val enc = key(v, "Encoding");
                if (!(enc.o instanceof PdfObj.Name) || (!enc.name().equals("Identity-H") && !enc.name().equals("Identity-V"))) {
                    return new Font(FontKind.COMPOSITE);
                }
                Font f = new Font(FontKind.IDENTITY);
                Val d = index(key(v, "DescendantFonts"), 0);
                Double dw = key(d, "DW").number();
                if (dw != null) f.dw = dw;
                Val w = key(d, "W");
                int n = Math.min(w.count(), MAX_W_ENTRIES);
                int[] budget = {MAX_W_ASSIGN};
                int i = 0;
                read:
                while (i < n) {
                    Double c0 = index(w, i).number();
                    if (c0 == null || i + 1 >= n) break;
                    Val arr = index(w, i + 1);
                    if (arr.isArray()) {
                        for (int j = 0; j < Math.min(arr.count(), MAX_W_ENTRIES); j++) {
                            Double x = index(arr, j).number();
                            if (x == null) continue;
                            if (!setW(f, budget, toLong(c0) + j, x)) break read;
                        }
                        i += 2;
                        continue;
                    }
                    Double c1 = index(w, i + 1).number();
                    Double x = index(w, i + 2).number();
                    if (c1 == null || x == null || i + 2 >= n) break;
                    long c = Math.max(toLong(c0), 0L);
                    long hi = toLong(c1);
                    while (c <= hi && c <= 0xFFFF) {
                        if (!setW(f, budget, c, x)) break read;
                        c++;
                    }
                    i += 3;
                }
                return f;
            }
            Font f = new Font(FontKind.SIMPLE);
            Double fc = key(v, "FirstChar").number();
            if (fc != null) f.first = toLong(fc);
            Val ws = key(v, "Widths");
            for (int i = 0; i < Math.min(ws.count(), 256); i++) f.widths.add(index(ws, i).number());
            Double mw = key(key(v, "FontDescriptor"), "MissingWidth").number();
            if (mw != null && mw > 0) f.missing = mw;
            return f;
        }

        private static boolean setW(Font f, int[] budget, long cid, double value) {
            budget[0]--;
            if (budget[0] < 0) return false;
            if (cid >= 0 && cid <= 0xFFFF && !f.w.containsKey(cid)) f.w.put(cid, value);
            return true;
        }

        private static double[] nums(List<Operand> ops, int n) {
            if (ops.size() != n) return null;
            double[] out = new double[n];
            for (int i = 0; i < n; i++) {
                if (!(ops.get(i) instanceof Num)) return null;
                out[i] = ((Num) ops.get(i)).v;
            }
            return out;
        }

        private static double[] textMatrix(double[] m) {
            if (!finite(m)) throw new Unscannable("text matrix");
            return m;
        }

        /** Executes one content stream from graphics state [g0], with its own operand stack, q stack, path and text matrices. */
        void run(byte[] content, Val res, GState g0, int depth) {
            Lexer l = new Lexer(content);
            GState g = g0.copy();
            List<GState> stack = new ArrayList<>();
            List<Subpath> path = new ArrayList<>();
            double[] tm = IDENTITY;
            double[] tlm = IDENTITY;
            List<Operand> opnds = new ArrayList<>();
            int[] count = {0};
            while (true) {
                Token t = l.next();
                if (t.kind == Token.EOF) return;
                if (t.kind == Token.ARR_END || t.kind == Token.DICT_END) continue;
                if (t.kind == Token.OBJ) {
                    Lexer.Completed x = l.obj(t.o, t.open, 0, count);
                    if (x.eof) return;
                    count[0]++;
                    if (count[0] > MAX_OPERANDS) throw new Unscannable("operands");
                    opnds.add(x.o);
                    continue;
                }
                String kw = t.kw;
                ops++;
                if (ops > MAX_OPS) throw new Unscannable("operators");
                List<Operand> args = new ArrayList<>(opnds);
                opnds.clear();
                count[0] = 0;
                double[] v;
                switch (kw) {
                    case "q":
                    case "Q":
                    case "BT":
                        if (!args.isEmpty()) continue;
                        if (kw.equals("BT")) {
                            tm = IDENTITY;
                            tlm = IDENTITY;
                        } else if (kw.equals("Q")) {
                            if (!stack.isEmpty()) g = stack.remove(stack.size() - 1);
                        } else {
                            if (stack.size() >= MAX_SAVE) throw new Unscannable("q nesting");
                            stack.add(g.copy());
                        }
                        break;
                    case "cm":
                        v = nums(args, 6);
                        if (v != null) {
                            g.ctm = mul(v, g.ctm);
                            if (!finite(g.ctm)) throw new Unscannable("CTM");
                        }
                        break;
                    case "w":
                        v = nums(args, 1);
                        if (v != null) g.lw = v[0];
                        break;
                    case "g":
                        v = nums(args, 1);
                        if (v != null) g.fillWhite = v[0] >= 1;
                        break;
                    case "G":
                        v = nums(args, 1);
                        if (v != null) g.strokeWhite = v[0] >= 1;
                        break;
                    case "rg":
                        v = nums(args, 3);
                        if (v != null) g.fillWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1;
                        break;
                    case "RG":
                        v = nums(args, 3);
                        if (v != null) g.strokeWhite = v[0] >= 1 && v[1] >= 1 && v[2] >= 1;
                        break;
                    case "k":
                        v = nums(args, 4);
                        if (v != null) g.fillWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0;
                        break;
                    case "K":
                        v = nums(args, 4);
                        if (v != null) g.strokeWhite = v[0] <= 0 && v[1] <= 0 && v[2] <= 0 && v[3] <= 0;
                        break;
                    case "cs":
                    case "sc":
                    case "scn":
                        g.fillWhite = false;
                        break;
                    case "CS":
                    case "SC":
                    case "SCN":
                        g.strokeWhite = false;
                        break;

                    // ── Path construction (points transformed by the CTM when given) ──
                    case "m":
                        v = nums(args, 2);
                        if (v != null) {
                            double[] p = apply(g.ctm, v[0], v[1]);
                            path.add(new Subpath(p[0], p[1]));
                        }
                        break;
                    case "l":
                    case "c":
                    case "v":
                    case "y": {
                        int n = kw.equals("l") ? 2 : kw.equals("c") ? 6 : 4;
                        v = nums(args, n);
                        if (v == null || path.isEmpty()) continue;
                        Subpath sp = path.get(path.size() - 1);
                        Rect seg = new Rect(sp.cx, sp.cy);
                        for (int i = 0; i < n; i += 2) {
                            double[] p = apply(g.ctm, v[i], v[i + 1]);
                            seg.add(p[0], p[1]);
                            sp.bbox.add(p[0], p[1]);
                            sp.cx = p[0];
                            sp.cy = p[1];
                        }
                        sp.segs.add(seg);
                        break;
                    }
                    case "h":
                        if (args.isEmpty() && !path.isEmpty()) path.get(path.size() - 1).close();
                        break;
                    case "re":
                        v = nums(args, 4);
                        if (v != null) {
                            double[] p0 = apply(g.ctm, v[0], v[1]);
                            double[] p1 = apply(g.ctm, v[0] + v[2], v[1]);
                            double[] p2 = apply(g.ctm, v[0] + v[2], v[1] + v[3]);
                            double[] p3 = apply(g.ctm, v[0], v[1] + v[3]);
                            Subpath sp = new Subpath(p0[0], p0[1]);
                            for (double[] p : new double[][] {p1, p2, p3}) {
                                Rect seg = new Rect(sp.cx, sp.cy);
                                seg.add(p[0], p[1]);
                                sp.segs.add(seg);
                                sp.bbox.add(p[0], p[1]);
                                sp.cx = p[0];
                                sp.cy = p[1];
                            }
                            sp.close();
                            path.add(sp);
                        }
                        break;
                    case "S":
                    case "s":
                    case "f":
                    case "F":
                    case "f*":
                    case "B":
                    case "B*":
                    case "b":
                    case "b*":
                    case "n": {
                        if (!args.isEmpty()) continue;
                        if ((kw.equals("s") || kw.equals("b") || kw.equals("b*")) && !path.isEmpty()) path.get(path.size() - 1).close();
                        boolean fill = !kw.equals("S") && !kw.equals("s") && !kw.equals("n");
                        boolean stroke = kw.equals("S") || kw.equals("s") || kw.equals("B") || kw.equals("B*") || kw.equals("b") || kw.equals("b*");
                        if (fill && !g.fillWhite) fill(path);
                        if (stroke && !g.strokeWhite) stroke(path, g);
                        path = new ArrayList<>();
                        break;
                    }

                    // ── Text ──
                    case "Tc":
                        v = nums(args, 1);
                        if (v != null) g.tc = v[0];
                        break;
                    case "Tw":
                        v = nums(args, 1);
                        if (v != null) g.tw = v[0];
                        break;
                    case "Tz":
                        v = nums(args, 1);
                        if (v != null) g.th = v[0] / 100;
                        break;
                    case "TL":
                        v = nums(args, 1);
                        if (v != null) g.tl = v[0];
                        break;
                    case "Ts":
                        v = nums(args, 1);
                        if (v != null) g.trise = v[0];
                        break;
                    case "Tf":
                        if (args.size() == 2 && args.get(0) instanceof Name && args.get(1) instanceof Num) {
                            g.font = font(key(key(res, "Font"), ((Name) args.get(0)).v));
                            g.tfs = ((Num) args.get(1)).v;
                        }
                        break;
                    case "Td":
                    case "TD":
                        v = nums(args, 2);
                        if (v != null) {
                            if (kw.equals("TD")) g.tl = -v[1];
                            tlm = textMatrix(mul(new double[] {1.0, 0.0, 0.0, 1.0, v[0], v[1]}, tlm));
                            tm = tlm;
                        }
                        break;
                    case "T*":
                        if (args.isEmpty()) {
                            tlm = textMatrix(mul(new double[] {1.0, 0.0, 0.0, 1.0, 0.0, -g.tl}, tlm));
                            tm = tlm;
                        }
                        break;
                    case "Tm":
                        v = nums(args, 6);
                        if (v != null) {
                            tm = v;
                            tlm = v;
                        }
                        break;
                    case "Tj":
                    case "'":
                    case "\"":
                    case "TJ": {
                        List<Operand> items;
                        if ((kw.equals("Tj") || kw.equals("'")) && args.size() == 1 && args.get(0) instanceof Str) {
                            items = args;
                        } else if (kw.equals("\"") && args.size() == 3 && args.get(0) instanceof Num && args.get(1) instanceof Num
                            && args.get(2) instanceof Str) {
                            g.tw = ((Num) args.get(0)).v;
                            g.tc = ((Num) args.get(1)).v;
                            items = Collections.singletonList(args.get(2));
                        } else if (kw.equals("TJ") && args.size() == 1 && args.get(0) instanceof Arr) {
                            items = ((Arr) args.get(0)).items;
                        } else {
                            continue;
                        }
                        if (kw.equals("'") || kw.equals("\"")) {
                            tlm = textMatrix(mul(new double[] {1.0, 0.0, 0.0, 1.0, 0.0, -g.tl}, tlm));
                            tm = tlm;
                        }
                        tm = show(items, g, tm);
                        break;
                    }
                    case "Do": {
                        if (args.size() != 1 || !(args.get(0) instanceof Name)) continue;
                        Val x = key(key(res, "XObject"), ((Name) args.get(0)).v);
                        String st = key(x, "Subtype").name();
                        if (st.equals("Image")) {
                            unitSquare(g.ctm);
                        } else if (st.equals("Form")) {
                            if (!x.isStream()) continue;
                            if (depth + 1 > MAX_DEPTH) throw new Unscannable("form depth");
                            double[] fm = IDENTITY;
                            Val m = key(x, "Matrix");
                            if (m.isArray() && m.count() == 6) {
                                double[] mv = new double[6];
                                boolean ok = true;
                                for (int i = 0; i < 6; i++) {
                                    Double nn = index(m, i).number();
                                    if (nn == null) {
                                        ok = false;
                                        break;
                                    }
                                    mv[i] = nn;
                                }
                                if (ok) fm = mv;
                            }
                            double[] ctm = mul(fm, g.ctm);
                            if (!finite(ctm)) throw new Unscannable("form matrix");
                            Val fres = key(x, "Resources");
                            if (!fres.isDict()) fres = res;
                            byte[] b = stream(x);
                            GState fg = g.copy();
                            fg.ctm = ctm;
                            run(b, fres, fg, depth + 1);
                        }
                        break;
                    }
                    case "BI":
                        inlineImage(l, g.ctm);
                        break;
                    default:
                        break;
                }
            }
        }

        /** One box per subpath; a subpath box covering ≥ half of the page box is a background and is skipped. */
        private void fill(List<Subpath> path) {
            for (Subpath sp : path) {
                long[] q = quantise(sp.bbox);
                long w = Math.min(q[2], page[2]) - Math.max(q[0], page[0]);
                long h = Math.min(q[3], page[3]) - Math.max(q[1], page[1]);
                if (w > 0 && h > 0 && 2 * w * h >= (page[2] - page[0]) * (page[3] - page[1])) continue;
                boxes.add(q);
            }
        }

        /** One box per segment, widened by half the line width mapped through the CTM (|a|+|c|, |b|+|d|). */
        private void stroke(List<Subpath> path, GState g) {
            double hw = Math.abs(g.lw) / 2;
            double ex = hw * Math.abs(g.ctm[0]) + hw * Math.abs(g.ctm[2]);
            double ey = hw * Math.abs(g.ctm[1]) + hw * Math.abs(g.ctm[3]);
            for (Subpath sp : path) for (Rect r : sp.segs) emit(new Rect(r.x0 - ex, r.y0 - ey, r.x1 + ex, r.y1 + ey));
        }

        private void unitSquare(double[] ctm) {
            double[] p = apply(ctm, 0.0, 0.0);
            Rect r = new Rect(p[0], p[1]);
            for (double[] q : new double[][] {{1.0, 0.0}, {0.0, 1.0}, {1.0, 1.0}}) {
                double[] t = apply(ctm, q[0], q[1]);
                r.add(t[0], t[1]);
            }
            emit(r);
        }

        /**
         * One box per string/array operand: [min, max] of glyph extents in text space × [rise − 0.3·Tfs, rise + Tfs], through
         * Tm then the CTM. Returns the advanced Tm.
         */
        private double[] show(List<Operand> items, GState g, double[] tm) {
            double[] x = {0.0};
            double[][] ext = {null};
            for (Operand it : items) {
                if (it instanceof Num) {
                    x[0] -= ((Num) it).v / 1000 * g.tfs * g.th;
                } else if (it instanceof Str) {
                    g.font.glyphs(((Str) it).b, (w0, space) -> {
                        double gwa = w0 / 1000 * g.tfs;
                        double gw = gwa * g.th;
                        double xe = x[0] + gw;
                        double lo = Math.min(x[0], xe);
                        double hi = Math.max(x[0], xe);
                        if (ext[0] == null) {
                            ext[0] = new double[] {lo, hi};
                        } else {
                            ext[0][0] = Math.min(ext[0][0], lo);
                            ext[0][1] = Math.max(ext[0][1], hi);
                        }
                        double adv = gwa + g.tc;
                        if (space) adv += g.tw;
                        x[0] += adv * g.th;
                    });
                }
            }
            if (ext[0] != null) {
                double[] e = ext[0];
                double ya = g.trise + g.tfs * -0.3;
                double yb = g.trise + g.tfs;
                Rect r = null;
                for (double[] q : new double[][] {{e[0], ya}, {e[1], ya}, {e[0], yb}, {e[1], yb}}) {
                    double[] t = apply(tm, q[0], q[1]);
                    double[] d = apply(g.ctm, t[0], t[1]);
                    if (r == null) r = new Rect(d[0], d[1]);
                    else r.add(d[0], d[1]);
                }
                emit(r);
            }
            double[] out = mul(new double[] {1.0, 0.0, 0.0, 1.0, x[0], 0.0}, tm);
            if (!finite(out)) throw new Unscannable("text matrix");
            return out;
        }

        /**
         * BI <key value>… ID <data> EI: data ends at the first "EI" preceded by a whitespace byte and followed by a
         * whitespace byte or the end of the content. No EI → the content ends (no box).
         */
        private void inlineImage(Lexer l, double[] ctm) {
            int[] count = {0};
            while (true) {
                Token t = l.next();
                if (t.kind == Token.EOF) return;
                if (t.kind == Token.OBJ) {
                    if (l.obj(t.o, t.open, 0, count).eof) return;
                } else if (t.kind == Token.KEYWORD) {
                    if (t.kw.equals("ID")) break;
                }
            }
            byte[] b = l.b;
            if (l.i < b.length && Lexer.isSpace(b[l.i] & 0xff)) l.i++;
            for (int p = l.i; p + 1 < b.length; p++) {
                if (b[p] == 'E' && b[p + 1] == 'I' && p > 0 && Lexer.isSpace(b[p - 1] & 0xff) && (p + 2 == b.length || Lexer.isSpace(b[p + 2] & 0xff))) {
                    l.i = p + 2;
                    unitSquare(ctm);
                    return;
                }
            }
            l.i = b.length;
        }

        /** /Rect of every annotation except /Popup, hidden (/F bit 2) or NoView (/F bit 6) and zero-area rects. */
        void annots(Val a) {
            if (!a.isArray()) return;
            if (a.count() > MAX_ANNOTS) throw new Unscannable("annotations");
            for (int i = 0; i < a.count(); i++) {
                Val an = index(a, i);
                if (!an.isDict() || key(an, "Subtype").name().equals("Popup")) continue;
                PdfObj f = key(an, "F").o;
                if (f instanceof PdfObj.Int && (((PdfObj.Int) f).v() & (2L | 32L)) != 0L) continue;
                Val rc = key(an, "Rect");
                if (!rc.isArray() || rc.count() != 4) continue;
                double[] v = new double[4];
                boolean ok = true;
                for (int j = 0; j < 4; j++) {
                    Double n = index(rc, j).number();
                    if (n == null) {
                        ok = false;
                        break;
                    }
                    v[j] = n;
                }
                if (!ok || v[0] == v[2] || v[1] == v[3]) continue;
                emit(new Rect(Math.min(v[0], v[2]), Math.min(v[1], v[3]), Math.max(v[0], v[2]), Math.max(v[1], v[3])));
            }
        }
    }

    /**
     * zlib (RFC 1950) inflate, strict: valid header, raw deflate to its final block, Adler-32 must match; FDICT only with
     * DICTID 1 (Go); truncation or any error → unscannable; bytes after the checksum are ignored; output over [limit] →
     * unscannable.
     */
    static byte[] inflate(byte[] input, int limit) {
        Inflater inf = new Inflater();
        try {
            inf.setInput(input);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[64 << 10];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && inf.needsDictionary()) {
                    // FDICT: Go compress/zlib accepts a preset dictionary only when DICTID = Adler-32 of its nil
                    // dictionary (1) and inflates on; any other DICTID → ErrDictionary.
                    if (inf.getAdler() != 1) throw new Unscannable("FlateDecode: preset dictionary");
                    inf.setDictionary(new byte[0]);
                    continue;
                }
                if (n == 0 && inf.needsInput()) throw new Unscannable("FlateDecode truncated");
                out.write(buf, 0, n);
                if (out.size() > limit) throw new Unscannable("content bytes");
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new Unscannable("FlateDecode: " + e.getMessage());
        } finally {
            inf.end();
        }
    }
}
