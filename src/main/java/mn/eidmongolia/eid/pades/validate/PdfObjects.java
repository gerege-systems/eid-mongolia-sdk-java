package mn.eidmongolia.eid.pades.validate;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.Adler32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Strict PDF object model for the revision classifier: a 1:1 port of the TS SDK src/pades/validate/pdfobj.ts (itself a
 * port of the Go SDK pades/internal/validate/pdfobj.go). Rejecting, not lenient: anything not understood is a
 * {@link PdfObjError}.
 *
 * <p>Value mapping (TS → Java): null → null, boolean → Boolean, bigint (int64) → Long, PReal → PReal, PName → PName,
 * PStr (latin1 string) → PStr, PRef → PRef, PVal[] → List&lt;Object&gt;, PDict → Map&lt;String,Object&gt; (insertion
 * ordered, never a null value), PStream → PStream.
 */
final class PdfObjects {
    private PdfObjects() {}

    static final int MAX_PDF_DEPTH = 64;
    static final int MAX_PDF_NODES = 1_000_000;
    static final int MAX_PDF_INFLATE = 64 << 20;
    static final long MAX_PDF_COPY = 256L << 20;
    static final int MAX_XREF_SECTIONS = 128;
    static final int MAX_OBJECT_NUMBER = 1 << 23;

    static final class PRef {
        final int num;
        final int gen;

        PRef(int num, int gen) {
            this.num = num;
            this.gen = gen;
        }
    }

    static final class PName {
        final String v;

        PName(String v) {
            this.v = v;
        }
    }

    /** A PDF string; v holds the raw bytes as a latin1 string (one char per byte). */
    static final class PStr {
        final String v;

        PStr(String v) {
            this.v = v;
        }
    }

    static final class PReal {
        final double v;

        PReal(double v) {
            this.v = v;
        }
    }

    static final class PStream {
        final Map<String, Object> dict;
        final byte[] data;

        PStream(Map<String, Object> dict, byte[] data) {
            this.dict = dict;
            this.data = data;
        }
    }

    // ── predicates ──

    static boolean isDict(Object v) {
        return v instanceof Map;
    }

    static boolean isArr(Object v) {
        return v instanceof List;
    }

    static boolean isInt(Object v) {
        return v instanceof Long;
    }

    static boolean isName(Object v, String s) {
        return v instanceof PName && (s == null || ((PName) v).v.equals(s));
    }

    static boolean isStr(Object v) {
        return v instanceof PStr;
    }

    static boolean isRef(Object v) {
        return v instanceof PRef;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> dict(Object v) {
        return (Map<String, Object>) v;
    }

    @SuppressWarnings("unchecked")
    static List<Object> arr(Object v) {
        return (List<Object>) v;
    }

    /** Go {@code d[k]}: null when absent (or when d is null). */
    static Object dget(Map<String, Object> d, String k) {
        return d == null ? null : d.get(k);
    }

    /** Go panic on comparing uncomparable interface values (TS GoPanic): not a PdfObjError. */
    static final class GoPanic extends RuntimeException {
        private static final long serialVersionUID = 1L;

        GoPanic() {
            super("comparing uncomparable type", null, false, false);
        }
    }

    private static int kindOf(Object v) {
        if (v instanceof Boolean) return 1;
        if (v instanceof Long) return 2;
        if (v instanceof PReal) return 3;
        if (v instanceof PName) return 4;
        if (v instanceof PStr) return 5;
        if (v instanceof PRef) return 6;
        if (v instanceof List) return 7;
        if (v instanceof Map) return 8;
        return 9;
    }

    /** Go interface {@code ==} (TS pdfobj.ts ifaceEq). */
    static boolean ifaceEq(Object a, Object b) {
        if (a == null || b == null) return a == b;
        int ta = kindOf(a);
        if (ta != kindOf(b)) return false;
        switch (ta) {
            case 1:
            case 2:
                return a.equals(b);
            case 3:
                return ((PReal) a).v == ((PReal) b).v;
            case 4:
                return ((PName) a).v.equals(((PName) b).v);
            case 5:
                return ((PStr) a).v.equals(((PStr) b).v);
            case 6:
                return ((PRef) a).num == ((PRef) b).num && ((PRef) a).gen == ((PRef) b).gen;
            default:
                throw new GoPanic();
        }
    }

    /** Structural equality: refs not followed, streams by dict + raw bytes; 90 != 90.0. */
    static boolean pdfEqual(Object a, Object b) {
        if (a == null) return b == null;
        if (isArr(a)) {
            if (!isArr(b)) return false;
            List<Object> x = arr(a);
            List<Object> y = arr(b);
            if (x.size() != y.size()) return false;
            for (int i = 0; i < x.size(); i++) if (!pdfEqual(x.get(i), y.get(i))) return false;
            return true;
        }
        if (isDict(a)) {
            if (!isDict(b)) return false;
            Map<String, Object> x = dict(a);
            Map<String, Object> y = dict(b);
            if (x.size() != y.size()) return false;
            for (Map.Entry<String, Object> e : x.entrySet()) {
                if (!y.containsKey(e.getKey()) || !pdfEqual(e.getValue(), y.get(e.getKey()))) return false;
            }
            return true;
        }
        if (a instanceof PStream) {
            if (!(b instanceof PStream)) return false;
            PStream x = (PStream) a;
            PStream y = (PStream) b;
            if (!Arrays.equals(x.data, y.data)) return false;
            return pdfEqual(x.dict, y.dict);
        }
        if (b == null) return false;
        return ifaceEq(a, b);
    }

    /** Every ref inside v (direct nesting only; refs are not followed). */
    static void pdfRefs(Object v, Consumer<PRef> f) {
        if (v instanceof PRef) f.accept((PRef) v);
        else if (isArr(v)) {
            for (Object e : arr(v)) pdfRefs(e, f);
        } else if (isDict(v)) {
            for (Object e : dict(v).values()) pdfRefs(e, f);
        } else if (v instanceof PStream) pdfRefs(((PStream) v).dict, f);
    }

    // ── xref entries ──

    static final int ENT_FREE = 1;
    static final int ENT_USE = 2;
    static final int ENT_COMP = 3;

    /** ENT_USE: off = byte offset; ENT_COMP: off = ObjStm number, idx = index inside. kind 0 = Go zero value. */
    static final class XrefEnt {
        final int kind;
        final long off;
        final long gen;
        final long idx;

        XrefEnt(int kind, long off, long gen, long idx) {
            this.kind = kind;
            this.off = off;
            this.gen = gen;
            this.idx = idx;
        }
    }

    static final XrefEnt ZERO = new XrefEnt(0, 0, 0, 0);
    static final XrefEnt FREE = new XrefEnt(ENT_FREE, 0, 0, 0);

    static boolean inUse(XrefEnt e) {
        return e.kind == ENT_USE || e.kind == ENT_COMP;
    }

    static boolean entEq(XrefEnt a, XrefEnt b) {
        return a.kind == b.kind && a.off == b.off && a.gen == b.gen && a.idx == b.idx;
    }

    /** Go {@code m[num]}: zero entry when absent. */
    static XrefEnt ent(Map<Integer, XrefEnt> m, long n) {
        if (n < Integer.MIN_VALUE || n > Integer.MAX_VALUE) return ZERO;
        XrefEnt e = m.get((int) n);
        return e == null ? ZERO : e;
    }

    /** An in-use row pointing at offset 0 (macOS Quartz) is an undefined (free) object. */
    static XrefEnt useEnt(long off, long gen) {
        if (off == 0) return FREE;
        return new XrefEnt(ENT_USE, off, gen, 0);
    }

    static final class XrefSection {
        final int off;
        int start;
        int end;
        Map<String, Object> trailer = new java.util.LinkedHashMap<>();
        final Map<Integer, XrefEnt> ents = new java.util.LinkedHashMap<>();

        XrefSection(int off, int start) {
            this.off = off;
            this.start = start;
        }
    }

    static final class ObjStm {
        final byte[] data;
        final List<Integer> nums = new ArrayList<>();
        final List<Integer> offs = new ArrayList<>();
        final int first;

        ObjStm(byte[] data, int first) {
            this.data = data;
            this.first = first;
        }
    }

    /** Cached parsed object (TS CachedObj). */
    static final class CachedObj {
        final int num;
        final int gen;
        final Object val;
        final int end;

        CachedObj(int num, int gen, Object val, int end) {
            this.num = num;
            this.gen = gen;
            this.val = val;
            this.end = end;
        }
    }

    /** Work budget and parse caches shared by all views of one document (TS PdfBudget). */
    static final class PdfBudget {
        int nodes = MAX_PDF_NODES;
        long inflate = MAX_PDF_INFLATE;
        /** Bytes the parser may copy out of the document for streams (each cached object is copied once). */
        long copy = MAX_PDF_COPY;
        final Map<String, CachedObj> objs = new HashMap<>();
        final Map<Long, ObjStm> stms = new HashMap<>();

        void node() {
            if (--nodes < 0) throw PdfObjError.limit();
        }

        void copy(long n) {
            copy -= n;
            if (copy < 0) throw PdfObjError.limit();
        }

        private static Object single(Object v) {
            if (!isArr(v)) return v;
            List<Object> a = arr(v);
            if (a.isEmpty()) return null;
            if (a.size() == 1) return a.get(0);
            throw PdfObjError.syntax();
        }

        /** Stream content of an xref / object stream: no filter or one FlateDecode (+ PNG predictor). */
        byte[] decode(PStream s) {
            Object filter = single(dget(s.dict, "Filter"));
            if (filter == null) return s.data;
            if (!ifaceEq(filter, new PName("FlateDecode"))) throw PdfObjError.syntax();
            byte[] out = zlibStrict(s.data, inflate);
            inflate -= out.length;
            if (inflate < 0) throw PdfObjError.limit();
            Object parms = single(dget(s.dict, "DecodeParms"));
            if (parms == null) return out;
            if (!isDict(parms)) throw PdfObjError.syntax();
            Map<String, Object> p = dict(parms);
            long pred = intOr(p, "Predictor", 1);
            long cols = intOr(p, "Columns", 1);
            if (pred == 1) return out;
            if (pred < 10 || pred > 15 || cols < 1 || cols > (1L << 16) || intOr(p, "Colors", 1) != 1
                || intOr(p, "BitsPerComponent", 8) != 8) {
                throw PdfObjError.syntax();
            }
            return unPNG(out, (int) cols);
        }

        private static long intOr(Map<String, Object> d, String key, long def) {
            Object v = dget(d, key);
            if (v == null) return def;
            if (isInt(v)) return (Long) v;
            return -1;
        }
    }

    /**
     * Go compress/zlib + io.LimitReader(limit+1) (TS pdfobj.ts zlibStrict): header, a complete deflate stream and the
     * adler32 are required; output over limit is an errPDFLimit.
     */
    static byte[] zlibStrict(byte[] src, long limit) {
        if (src.length < 2) throw PdfObjError.syntax();
        int cmf = src[0] & 0xff;
        int flg = src[1] & 0xff;
        if ((cmf & 0x0f) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0 || (flg & 0x20) != 0) {
            throw PdfObjError.syntax();
        }
        Inflater inf = new Inflater(true);
        try {
            inf.setInput(src, 2, src.length - 2);
            byte[] out = new byte[(int) Math.min(limit, Math.max(1024L, (long) src.length * 4))];
            int len = 0;
            byte[] buf = new byte[16384];
            while (!inf.finished()) {
                int n;
                try {
                    n = inf.inflate(buf);
                } catch (DataFormatException e) {
                    throw PdfObjError.syntax();
                }
                if (n > 0) {
                    if ((long) len + n > limit) throw PdfObjError.limit();
                    if (len + n > out.length) {
                        long cap = Math.max(1L, out.length) * 2;
                        while (cap < len + n) cap *= 2;
                        out = Arrays.copyOf(out, (int) Math.min(cap, limit));
                    }
                    System.arraycopy(buf, 0, out, len, n);
                    len += n;
                } else if (!inf.finished()) {
                    // Truncated input (needsInput), a preset dictionary, or no progress: all syntax errors.
                    throw PdfObjError.syntax();
                }
            }
            int at = src.length - inf.getRemaining();
            if (at + 4 > src.length) throw PdfObjError.syntax();
            long want = ((long) (src[at] & 0xff) << 24) | ((src[at + 1] & 0xff) << 16) | ((src[at + 2] & 0xff) << 8)
                | (src[at + 3] & 0xff);
            Adler32 a = new Adler32();
            a.update(out, 0, len);
            if (a.getValue() != want) throw PdfObjError.syntax();
            return len == out.length ? out : Arrays.copyOf(out, len);
        } finally {
            inf.end();
        }
    }

    /** Undoes the PNG row predictor (one byte = one pixel). */
    static byte[] unPNG(byte[] in, int cols) {
        if (in.length % (cols + 1) != 0) throw PdfObjError.syntax();
        int rows = in.length / (cols + 1);
        byte[] out = new byte[rows * cols];
        int[] prev = new int[cols];
        for (int r = 0; r < rows; r++) {
            int base = r * (cols + 1);
            int ft = in[base] & 0xff;
            int[] cur = new int[cols];
            for (int i = 0; i < cols; i++) {
                int x = in[base + 1 + i] & 0xff;
                int left = 0;
                int upLeft = 0;
                if (i > 0) {
                    left = cur[i - 1];
                    upLeft = prev[i - 1];
                }
                int up = prev[i];
                switch (ft) {
                    case 0:
                        break;
                    case 1:
                        x = (x + left) & 0xff;
                        break;
                    case 2:
                        x = (x + up) & 0xff;
                        break;
                    case 3:
                        x = (x + ((left & up) + ((left ^ up) >> 1))) & 0xff;
                        break;
                    case 4: {
                        int pa = Math.abs(up - upLeft);
                        int pb = Math.abs(left - upLeft);
                        int pc = Math.abs(left + up - 2 * upLeft);
                        if (pa <= pb && pa <= pc) x = (x + left) & 0xff;
                        else if (pb <= pc) x = (x + up) & 0xff;
                        else x = (x + upLeft) & 0xff;
                        break;
                    }
                    default:
                        throw PdfObjError.syntax();
                }
                cur[i] = x;
                out[r * cols + i] = (byte) x;
            }
            prev = cur;
        }
        return out;
    }

    // ── lexical helpers ──

    static boolean isPDFSpace(int c) {
        return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    static boolean isPDFDelim(int c) {
        return c == '(' || c == ')' || c == '<' || c == '>' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/'
            || c == '%';
    }

    /** Whitespace allowed BETWEEN objects / xref sections (no NUL, no comments). */
    static boolean isGapSpace(int c) {
        return c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    static boolean allGapSpace(byte[] b, int from, int to) {
        for (int i = from; i < to; i++) if (!isGapSpace(b[i] & 0xff)) return false;
        return true;
    }

    static boolean isDigit(int c) {
        return c >= '0' && c <= '9';
    }

    static String latin1(byte[] b, int s, int e) {
        return new String(b, s, e - s, StandardCharsets.ISO_8859_1);
    }

    static byte[] latin1(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }
}
