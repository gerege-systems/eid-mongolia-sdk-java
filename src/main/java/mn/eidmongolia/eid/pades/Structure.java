package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import mn.eidmongolia.eid.internal.Text;

/**
 * PRECHECKS #2a / #2b — Go reference `validate.CheckStructure` (nesting.go + objstm.go, incl. the 2026-11-04 ObjStm
 * hardening), run before any PDF parsing: array/dictionary nesting > 256 from every point where a reader may start an
 * object (after the `obj` / `trailer` keywords, at every offset of a /Type /ObjStm header), a read/inflate budget,
 * top-level /Size > 2 097 152, and the object-stream graph. One layer of defence — it does not make untrusted PDF parsing
 * safe on its own.
 */
final class Structure {
    static final class Failure extends Exception {
        Failure() {
            super("PDF structure nested too deep or too complex");
        }
    }

    static final int MAX_NESTING = 256;
    private static final int SCAN_FACTOR = 16; // read budget = 16 × len(doc) + 1 MiB
    private static final int MAX_OBJSTM_BYTES = 32 << 20; // all inflated object streams together (zip bomb)
    static final long MAX_XREF_SIZE = 1L << 21;
    private static final int MAX_OBJSTM_CHAIN = 64;

    private Structure() {
    }

    static void check(byte[] doc) throws Failure {
        Scan s = new Scan((int) Math.min(Integer.MAX_VALUE, (long) SCAN_FACTOR * doc.length + (1 << 20)), MAX_OBJSTM_BYTES);
        for (String kws : new String[] {"obj", "trailer"}) {
            byte[] kw = Text.latin1(kws);
            int k = 0;
            while (true) {
                int at = PdfReader.indexOf(doc, kw, k);
                if (at < 0) break;
                int end = at + kw.length;
                k = end;
                // The keyword stands alone (`endobj`, `objx` are other keywords).
                if (at > 0 && !isSpace(doc[at - 1]) && !isDelim(doc[at - 1])) continue;
                if (end < doc.length && !isSpace(doc[end]) && !isDelim(doc[end])) continue;
                s.obj(doc, doc.length, end, true);
            }
        }
        if (s.bigSize) throw new Failure();
        checkObjStmGraph(doc);
    }

    /**
     * `/Encrypt` followed by an indirect reference (`N G R`) or a direct dictionary (`<<`) — Go regexp
     * `/Encrypt(?:\s+\d+\s+\d+\s+R|\s*<<)`; `/EncryptMetadata` does not count.
     */
    static boolean hasEncryptRef(byte[] b) {
        byte[] key = Text.latin1("/Encrypt");
        int from = 0;
        while (true) {
            int k = PdfReader.indexOf(b, key, from);
            if (k < 0) return false;
            from = k + 1;
            int q = k + key.length;
            while (ws(b, q)) q++;
            if (q + 1 < b.length && b[q] == '<' && b[q + 1] == '<') return true;
            int p = k + key.length;
            boolean ok = true;
            for (int r = 0; r < 2 && ok; r++) {
                int w = p;
                while (ws(b, p)) p++;
                int d = p;
                while (p < b.length && b[p] >= '0' && b[p] <= '9') p++;
                if (p == d || d == w) ok = false;
            }
            if (ok) {
                int w = p;
                while (ws(b, p)) p++;
                if (p > w && p < b.length && b[p] == 'R') return true;
            }
        }
    }

    private static boolean ws(byte[] b, int i) {
        if (i >= b.length) return false;
        int c = b[i];
        return c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    private static boolean isSpace(byte c) {
        return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    // ()<>[]{}/%
    private static boolean isDelim(byte c) {
        return c == 0x28 || c == 0x29 || c == 0x3C || c == 0x3E || c == 0x5B || c == 0x5D || c == 0x7B || c == 0x7D || c == 0x2F || c == 0x25;
    }

    private enum Tok { EOF, ERR, ARR, ARR_END, DICT, DICT_END, NAME, WORD, STR }

    /** digitorus buffer.readToken (structure only) over b[0 until end]. */
    private static final class Lex {
        final byte[] b;
        final int end;
        int pos;
        String v = "";

        Lex(byte[] b, int end, int pos) {
            this.b = b;
            this.end = end;
            this.pos = pos;
        }

        Tok next() {
            while (true) {
                while (pos < end && isSpace(b[pos])) pos++;
                if (pos < end && b[pos] == '%') {
                    while (pos < end && b[pos] != '\r' && b[pos] != '\n') pos++;
                    continue;
                }
                break;
            }
            if (pos >= end) return Tok.EOF;
            int c = b[pos] & 0xff;
            pos++;
            switch (c) {
                case 0x3C:
                    if (pos < end && b[pos] == '<') {
                        pos++;
                        return Tok.DICT;
                    }
                    while (pos < end && b[pos] != '>') pos++;
                    pos++;
                    return Tok.STR;
                case 0x28: {
                    int depth = 1;
                    while (pos < end && depth > 0) {
                        switch (b[pos]) {
                            case 0x28: depth++; break;
                            case 0x29: depth--; break;
                            case 0x5C: pos++; break;
                            default: break;
                        }
                        pos++;
                    }
                    return Tok.STR;
                }
                case 0x5B:
                    return Tok.ARR;
                case 0x5D:
                    return Tok.ARR_END;
                case 0x7B:
                case 0x7D:
                    v = String.valueOf((char) c);
                    return Tok.WORD;
                case 0x2F: {
                    StringBuilder sb = new StringBuilder();
                    while (pos < end && !isDelim(b[pos]) && !isSpace(b[pos])) {
                        if (b[pos] == '#' && pos + 2 < end) {
                            int hi = Text.hexVal(b[pos + 1] & 0xff);
                            int lo = Text.hexVal(b[pos + 2] & 0xff);
                            if (hi >= 0 && lo >= 0) {
                                sb.append((char) ((hi << 4) | lo));
                                pos += 3;
                                continue;
                            }
                        }
                        sb.append((char) (b[pos] & 0xff));
                        pos++;
                    }
                    v = sb.toString();
                    return Tok.NAME;
                }
                case 0x3E:
                    if (pos < end && b[pos] == '>') {
                        pos++;
                        return Tok.DICT_END;
                    }
                    return Tok.ERR;
                case 0x29:
                    return Tok.ERR;
                default:
                    break;
            }
            int start = pos - 1;
            while (pos < end && !isDelim(b[pos]) && !isSpace(b[pos])) pos++;
            v = new String(b, start, pos - start, StandardCharsets.ISO_8859_1);
            return Tok.WORD;
        }
    }

    private static final Pattern INT_RE = Pattern.compile("^[+-]?[0-9]+$");

    /** Go `strconv.ParseInt(s, 10, 64)` succeeds. */
    private static boolean isInt(String s) {
        return INT_RE.matcher(s).matches() && PdfLexer.toLong(s) != null;
    }

    /** Go `v, _ := strconv.ParseInt(s, 10, 64)`: syntax error → 0, out of range → ±MaxInt64. */
    private static long parseInt64(String s) {
        if (!INT_RE.matcher(s).matches()) return 0;
        Long v = PdfLexer.toLong(s);
        if (v != null) return v;
        return s.startsWith("-") ? Long.MIN_VALUE : Long.MAX_VALUE;
    }

    private static final class Frame {
        final boolean dict;
        boolean expectKey;
        String key = "";

        Frame(boolean dict, boolean expectKey) {
            this.dict = dict;
            this.expectKey = expectKey;
        }
    }

    private static final class Info {
        String typ = "";
        String filter = "";
        int filters;
        boolean parms;
        boolean indirect;
        long first;
        long nCount;
    }

    private static final Set<String> HEADER_KEYS = Set.of("Type", "Filter", "DecodeParms", "N", "First");

    private static final class Scan {
        int budget;
        int inflateLeft;
        boolean bigSize;

        Scan(int budget, int inflateLeft) {
            this.budget = budget;
            this.inflateLeft = inflateLeft;
        }

        /**
         * One reader object at [start] (a doubled `N G obj` included) in b[.. end), depth-checked; with [allowStream] a
         * top-level /Type /ObjStm dictionary's stream is inflated and its objects checked.
         */
        void obj(byte[] b, int end, int start, boolean allowStream) throws Failure {
            Lex l = new Lex(b, end, start);
            try {
                body(l, b, end, start, allowStream);
            } finally {
                budget -= l.pos - start;
            }
        }

        private void body(Lex l, byte[] b, int end, int start, boolean allowStream) throws Failure {
            List<Frame> stack = new ArrayList<>();
            Info info = new Info();
            while (true) {
                if (budget - (l.pos - start) < 0) throw new Failure();
                Tok tok = l.next();
                Frame top = stack.isEmpty() ? null : stack.get(stack.size() - 1);
                if (top != null && top.dict && top.expectKey) {
                    if (tok == Tok.DICT_END) {
                        stack.remove(stack.size() - 1);
                        if (stack.isEmpty()) {
                            if (allowStream && (info.typ.equals("ObjStm") || info.indirect)) objStm(b, end, l, info);
                            return;
                        }
                        Frame last = stack.get(stack.size() - 1);
                        last.expectKey = last.dict;
                        continue;
                    }
                    if (tok == Tok.NAME) {
                        top.key = l.v;
                        top.expectKey = false;
                        continue;
                    }
                    return; // non-name key — the reader fails here
                }
                switch (tok) {
                    case EOF:
                    case ERR:
                    case DICT_END:
                        return;
                    case ARR:
                    case DICT:
                        if (stack.size() >= MAX_NESTING) throw new Failure();
                        if (stack.size() == 1 && stack.get(0).dict && stack.get(0).key.equals("DecodeParms")) info.parms = true;
                        if (stack.size() == 1 && stack.get(0).dict && stack.get(0).key.equals("Filter")) {
                            info.filter = ""; // the last duplicate key wins; array names are counted below
                            info.filters = 0;
                        }
                        stack.add(new Frame(tok == Tok.DICT, tok == Tok.DICT));
                        continue;
                    case ARR_END:
                        if (top == null || top.dict) return;
                        stack.remove(stack.size() - 1);
                        break;
                    case WORD: {
                        boolean done = false;
                        if (isInt(l.v)) {
                            int save = l.pos;
                            String saveV = l.v;
                            if (l.next() == Tok.WORD && isInt(l.v)) {
                                Tok t3 = l.next();
                                if (t3 == Tok.WORD && l.v.equals("R")) {
                                    if (stack.size() == 1 && stack.get(0).dict && HEADER_KEYS.contains(stack.get(0).key)) info.indirect = true;
                                    // /Filter [6 0 R] — the reader resolves it and decodes (fail closed).
                                    if (stack.size() == 2 && stack.get(0).dict && stack.get(0).key.equals("Filter")) info.indirect = true;
                                    done = true; // a reference = one value
                                } else if (t3 == Tok.WORD && l.v.equals("obj")) {
                                    continue; // doubled `N G obj` — the next value continues this object
                                }
                            }
                            if (!done) {
                                l.pos = save;
                                l.v = saveV;
                            }
                        }
                        if (!done) noteScalar(stack, info, tok, l.v);
                        break;
                    }
                    case NAME:
                    case STR:
                        noteScalar(stack, info, tok, l.v);
                        break;
                    default:
                        break;
                }
                if (stack.isEmpty()) return;
                Frame last = stack.get(stack.size() - 1);
                if (last.dict) last.expectKey = true;
            }
        }

        private void noteScalar(List<Frame> stack, Info info, Tok tok, String v) {
            if (stack.size() == 1 && stack.get(0).dict) {
                switch (stack.get(0).key) {
                    case "Type":
                        if (tok == Tok.NAME) info.typ = v;
                        break;
                    case "Filter":
                        if (tok == Tok.NAME) {
                            info.filter = v;
                            info.filters = 1;
                        } else {
                            info.filter = ""; // null → read unfiltered; the last duplicate key wins
                            info.filters = 0;
                        }
                        break;
                    case "DecodeParms":
                        if (!(tok == Tok.WORD && v.equals("null"))) info.parms = true;
                        break;
                    case "N":
                        info.nCount = parseInt64(v);
                        break;
                    case "Size":
                        if (tok == Tok.WORD && isInt(v) && Long.parseLong(v) > MAX_XREF_SIZE) bigSize = true;
                        break;
                    case "First":
                        info.first = parseInt64(v);
                        break;
                    default:
                        break;
                }
            } else if (stack.size() == 2 && stack.get(0).dict && stack.get(0).key.equals("Filter") && !stack.get(1).dict && tok == Tok.NAME) {
                info.filter = v;
                info.filters++;
            }
        }

        /** The data after `stream` (FlateDecode ends on its own, whatever /Length says), objects at every header offset. */
        private void objStm(byte[] b, int end, Lex l, Info info) throws Failure {
            if (l.next() != Tok.WORD || !l.v.equals("stream")) return;
            if (info.indirect) throw new Failure(); // /Type /Filter /N /First by reference — never in a legitimate file
            if (!info.typ.equals("ObjStm")) return;
            int p = l.pos;
            if (p < end && b[p] == '\r') p++;
            if (p < end && b[p] == '\n') p++;
            p = Math.min(p, end);
            if (info.filters == 0) {
                objStmData(b, p, end, info); // unfiltered — the rest of the data
                return;
            }
            if (info.filters > 1) throw new Failure(); // chained filters are not replayed — fail closed
            if (!info.filter.equals("FlateDecode")) return; // the reader does not decode it
            if (info.parms) throw new Failure(); // predictor object streams are not replayed — fail closed
            byte[] data = inflatePrefix(b, p, end, inflateLeft);
            if (data == null) throw new Failure();
            inflateLeft -= data.length;
            budget -= data.length;
            objStmData(data, 0, data.length, info);
        }

        /**
         * Go objStmData (2026-11-04): the offset is computed as the reader does — a non-integer token is 0, a negative
         * offset / /First is kept (int64 wrap); a position before the data → failure; beyond its end → skipped.
         */
        private void objStmData(byte[] b, int base, int end, Info info) throws Failure {
            Lex l = new Lex(b, end, base);
            boolean firstDone = false;
            long len = end - base;
            for (long i = 0; i < info.nCount; i++) {
                if (l.next() == Tok.EOF) break;
                long off = 0;
                if (l.next() == Tok.WORD) {
                    Long v = PdfLexer.toLong(l.v);
                    if (v != null && INT_RE.matcher(l.v).matches()) off = v;
                }
                long at = info.first + off;
                if (at < 0) throw new Failure();
                if (at >= len || (at == info.first && firstDone)) continue;
                firstDone = firstDone || at == info.first;
                if (budget < 0) throw new Failure();
                obj(b, end, base + (int) at, false);
            }
            if (budget < 0) throw new Failure();
        }
    }

    /**
     * zlib-inflates the prefix of b[from, to) (stops at the end of the zlib stream or at the first error, keeping what
     * was produced — Go `io.ReadAll(zlib.NewReader)`); null = more than [limit] bytes came out.
     */
    private static byte[] inflatePrefix(byte[] b, int from, int to, int limit) {
        Inflater inf = new Inflater();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            inf.setInput(b, from, to - from);
            byte[] buf = new byte[64 << 10];
            while (!inf.finished()) {
                int n;
                try {
                    n = inf.inflate(buf);
                } catch (DataFormatException e) {
                    break;
                }
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break;
                out.write(buf, 0, n);
                if (out.size() > limit) return null;
            }
        } finally {
            inf.end();
        }
        return out.toByteArray();
    }

    /**
     * Go `checkObjStmGraph`: an object's container stream must not itself be in an object stream; the container's (and
     * its /Extends chain's) header must not reference objects inside object streams; /Extends must not cycle or exceed
     * 64. A reader that cannot open or parse the document is not judged here (the caller reports PDF_INVALID).
     */
    private static void checkObjStmGraph(byte[] doc) throws Failure {
        PdfReader r;
        try {
            r = PdfReader.open(doc);
        } catch (Exception e) {
            return;
        }
        Map<Integer, PdfReader.XrefEntry> xr = r.xref;
        TreeSet<Integer> containers = new TreeSet<>();
        for (PdfReader.XrefEntry e : xr.values()) {
            if (!e.compressed) continue;
            if (inStream(xr, new PdfRef(e.stream, 0))) throw new Failure();
            containers.add(e.stream);
        }
        for (int c : containers) {
            Set<PdfRef> seen = new HashSet<>();
            PdfRef p = new PdfRef(c, 0);
            while (registered(xr, p)) {
                if (seen.contains(p) || seen.size() > MAX_OBJSTM_CHAIN) throw new Failure();
                seen.add(p);
                PdfReader.XrefEntry e = xr.get(p.id());
                if (e.compressed) break;
                Object[] h = r.rawHeader(e.off, p.id());
                if (h == null) return;
                if (!(Boolean) h[1]) break;
                PdfDict hdr = (PdfDict) h[0];
                boolean[] bad = {false};
                walkRefs(new PdfObj.Dict(hdr), 0, ref -> {
                    if (inStream(xr, ref)) bad[0] = true;
                });
                if (bad[0]) throw new Failure();
                PdfObj ext = hdr.get("Extends");
                if (!(ext instanceof PdfObj.Ref)) break;
                p = ((PdfObj.Ref) ext).r();
            }
        }
    }

    private static boolean registered(Map<Integer, PdfReader.XrefEntry> xr, PdfRef p) {
        PdfReader.XrefEntry e = xr.get(p.id());
        if (e == null) return false;
        return e.compressed ? p.gen() == 0 : e.gen == p.gen();
    }

    private static boolean inStream(Map<Integer, PdfReader.XrefEntry> xr, PdfRef p) {
        PdfReader.XrefEntry e = xr.get(p.id());
        return e != null && e.compressed && registered(xr, p);
    }

    private static void walkRefs(PdfObj v, int depth, java.util.function.Consumer<PdfRef> fn) {
        if (depth > MAX_NESTING) return;
        if (v instanceof PdfObj.Ref) {
            fn.accept(((PdfObj.Ref) v).r());
        } else if (v instanceof PdfObj.Dict || v instanceof PdfObj.Stream) {
            for (PdfObj x : v.dict().entries.values()) walkRefs(x, depth + 1, fn);
        } else if (v instanceof PdfObj.Arr) {
            for (PdfObj x : ((PdfObj.Arr) v).items()) walkRefs(x, depth + 1, fn);
        }
    }
}
