package mn.eidmongolia.eid.pades.validate;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * PDF reader for signature extraction — a 1:1 port of TS src/pades/pdf/reader.ts (itself a port of github.com/digitorus/pdf
 * v0.1.2 read.go / lex.go, which the Go reference validator uses): the same xref table / stream handling, object
 * streams (/Extends), PNG Up predictor and quirks (null-valued keys kept, keys() in byte order). Hardening on top of the
 * reference (only hostile inputs are affected): bounded recursion depth, a per-reader inflate budget, and decoded object
 * streams cached so one stream is never inflated once per member object.
 */
final class DReader {
    static final class PdfError extends RuntimeException {
        PdfError(String m) {
            super(m);
        }
    }

    /** PDF null (a present key with a null value — digitorus keeps it in Keys()). */
    static final Object NULL = new Object() {
        @Override
        public String toString() {
            return "null";
        }
    };

    static final class PReal {
        final double v;

        PReal(double v) {
            this.v = v;
        }
    }

    static final class PStr {
        final byte[] b;

        PStr(byte[] b) {
            this.b = b;
        }
    }

    static final class PName {
        final String n;

        PName(String n) {
            this.n = n;
        }
    }

    static final class PRef {
        final int id;
        final int gen;

        PRef(int id, int gen) {
            this.id = id;
            this.gen = gen;
        }
    }

    static final class PKeyword {
        final String k;

        PKeyword(String k) {
            this.k = k;
        }
    }

    static final class PStream {
        final Map<String, Object> hdr;
        final int[] ptr;
        final int offset;

        PStream(Map<String, Object> hdr, int[] ptr, int offset) {
            this.hdr = hdr;
            this.ptr = ptr;
            this.offset = offset;
        }
    }

    private static final class ObjDef {
        final int[] ptr;
        final Object obj;

        ObjDef(int[] ptr, Object obj) {
            this.ptr = ptr;
            this.obj = obj;
        }
    }

    private static final Object EOF = new Object();
    static final int[] NO_PTR = {0, 0};
    /** Recursion bound (the structure pre-check already rejects nesting > 256; this keeps the stack safe regardless). */
    private static final int MAX_DEPTH = 512;
    /** Per-stream inflate limit (TS zlibInflate default). */
    private static final int MAX_STREAM = 64 << 20;
    /** Total bytes one reader may copy or inflate from streams. */
    private static final long MAX_WORK_TOTAL = 256L << 20;
    /** Decoded streams kept for re-use (object streams), in bytes. */
    private static final long MAX_CACHE_BYTES = 64L << 20;
    /** Object ids a cross-reference section may add (Go writer guard, 2^21). */
    private static final long MAX_XREF_IDS = 1L << 21;
    /** Cross-reference sections followed through /Prev. */
    private static final int MAX_XREF_SECTIONS = 128;

    private static boolean isSpace(int c) {
        return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
    }

    private static boolean isDelim(int c) {
        return c == '<' || c == '>' || c == '(' || c == ')' || c == '[' || c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
    }

    private static int unhex(int c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    private static boolean isKw(Object t, String k) {
        return t instanceof PKeyword && ((PKeyword) t).k.equals(k);
    }

    private static final Pattern INT = Pattern.compile("^[+-]?[0-9]+$");
    private static final Pattern REAL1 = Pattern.compile("^[+-]?[0-9.]+$");
    private static final Pattern REAL2 = Pattern.compile("^[+-]?[^.]*\\.[^.]*$");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern DOT = Pattern.compile("^[+-]?\\.$");

    /** digitorus lex.go buffer over data[start:]. */
    private static final class Lexer {
        private final byte[] data;
        private final boolean allowEOF;
        int pos;
        boolean eof;
        private final Deque<Object> unread = new ArrayDeque<>();
        int[] objptr = NO_PTR;
        private int depth;

        Lexer(byte[] data, int start, boolean allowEOF) {
            this.data = data;
            this.pos = start;
            this.allowEOF = allowEOF;
        }

        int readByte() {
            if (pos >= data.length || pos < 0) {
                if (!allowEOF) throw new PdfError("malformed PDF: reading at offset " + pos + ": EOF");
                eof = true;
                pos = data.length + 1;
                return 10;
            }
            return data[pos++] & 0xff;
        }

        void unreadByte() {
            if (pos > 0) pos--;
        }

        void unreadToken(Object t) {
            unread.push(t);
        }

        Object readToken() {
            if (!unread.isEmpty()) return unread.pop();
            int c = readByte();
            for (;;) {
                if (isSpace(c)) {
                    if (eof) return EOF;
                    c = readByte();
                } else if (c == '%') {
                    while (c != 13 && c != 10) c = readByte();
                } else {
                    break;
                }
            }
            switch (c) {
                case '<':
                    if (readByte() == '<') return new PKeyword("<<");
                    unreadByte();
                    return readHexString();
                case '(':
                    return readLiteralString();
                case '[':
                case ']':
                case '{':
                case '}':
                    return new PKeyword(String.valueOf((char) c));
                case '/':
                    return readName();
                case '>':
                    if (readByte() == '>') return new PKeyword(">>");
                    unreadByte();
                    // fallthrough
                default:
                    if (isDelim(c)) throw new PdfError("unexpected delimiter " + (char) c);
                    unreadByte();
                    return readKeyword();
            }
        }

        private PStr readHexString() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            for (;;) {
                int c = readByte();
                while (isSpace(c) && !eof) c = readByte();
                if (eof) throw new PdfError("unterminated hex string");
                if (c == '>') break;
                int c2 = readByte();
                while (isSpace(c2) && !eof) c2 = readByte();
                if (eof) throw new PdfError("unterminated hex string");
                if (unhex(c) < 0 || unhex(c2) < 0) throw new PdfError("malformed hex string");
                out.write((unhex(c) << 4) | unhex(c2));
            }
            return new PStr(out.toByteArray());
        }

        private PStr readLiteralString() {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int depth = 1;
            for (;;) {
                int c = readByte();
                if (eof) throw new PdfError("unterminated literal string");
                if (c == '(') {
                    depth++;
                    out.write(c);
                } else if (c == ')') {
                    if (--depth == 0) break;
                    out.write(c);
                } else if (c == '\\') {
                    c = readByte();
                    switch (c) {
                        case 'n': out.write(10); break;
                        case 'r': out.write(13); break;
                        case 'b': out.write(8); break;
                        case 't': out.write(9); break;
                        case 'f': out.write(12); break;
                        case '(':
                        case ')':
                        case '\\':
                            out.write(c);
                            break;
                        case 13:
                            if (readByte() != 10) unreadByte();
                            break;
                        case 10:
                            break;
                        default:
                            if (c >= '0' && c <= '7') {
                                int x = c - '0';
                                for (int i = 0; i < 2; i++) {
                                    c = readByte();
                                    if (c < '0' || c > '7') {
                                        unreadByte();
                                        break;
                                    }
                                    x = x * 8 + (c - '0');
                                }
                                if (x > 255) throw new PdfError("invalid octal escape");
                                out.write(x);
                            } else {
                                throw new PdfError("invalid escape sequence");
                            }
                    }
                } else {
                    out.write(c);
                }
            }
            return new PStr(out.toByteArray());
        }

        private PName readName() {
            StringBuilder s = new StringBuilder();
            for (;;) {
                int c = readByte();
                if (isDelim(c) || isSpace(c)) {
                    unreadByte();
                    break;
                }
                if (c == '#') {
                    int h = unhex(readByte());
                    int l = unhex(readByte());
                    if (h < 0 || l < 0) throw new PdfError("malformed name");
                    s.append((char) ((h << 4) | l));
                    continue;
                }
                s.append((char) c);
            }
            return new PName(s.toString());
        }

        private Object readKeyword() {
            StringBuilder sb = new StringBuilder();
            for (;;) {
                int c = readByte();
                if (isDelim(c) || isSpace(c)) {
                    unreadByte();
                    break;
                }
                sb.append((char) c);
            }
            String s = sb.toString();
            if (s.equals("true")) return Boolean.TRUE;
            if (s.equals("false")) return Boolean.FALSE;
            if (INT.matcher(s).matches()) {
                // Bounded: digit strings longer than any int64 are rejected before parsing (a huge token must not cost
                // quadratic BigInteger work). Same outcome as TS (out of int64 range → error).
                boolean neg = s.startsWith("-");
                int z = s.startsWith("+") || neg ? 1 : 0;
                while (z < s.length() - 1 && s.charAt(z) == '0') z++;
                String digits = s.substring(z);
                if (digits.length() > 19) throw new PdfError("invalid integer");
                try {
                    return Long.parseLong(neg ? "-" + digits : digits);
                } catch (NumberFormatException e) {
                    throw new PdfError("invalid integer");
                }
            }
            if (REAL1.matcher(s).matches() && REAL2.matcher(s).matches() && DIGIT.matcher(s).find()) {
                // JS parseFloat on [+-]?digits.digits — never NaN here (a digit is present).
                String t = s.startsWith("+") ? s.substring(1) : s;
                if (t.startsWith("-.")) t = "-0" + t.substring(1);
                else if (t.startsWith(".")) t = "0" + t;
                if (t.endsWith(".")) t = t + "0";
                return new PReal(Double.parseDouble(t));
            }
            if (DOT.matcher(s).matches()) throw new PdfError("invalid real " + s);
            return new PKeyword(s);
        }

        Object readObject() {
            if (++depth > MAX_DEPTH) throw new PdfError("PDF nesting too deep");
            try {
                return readObject0();
            } finally {
                depth--;
            }
        }

        private Object readObject0() {
            Object tok = readToken();
            if (tok instanceof PKeyword) {
                switch (((PKeyword) tok).k) {
                    case "null":
                        return NULL;
                    case "endobj":
                        unreadToken(tok);
                        return NULL;
                    case "<<":
                        return readDict();
                    case "[":
                        return readArray();
                    default:
                        throw new PdfError("unexpected keyword parsing object");
                }
            }
            if (tok instanceof Long && (Long) tok >= 0 && (Long) tok <= 0xffffffffL) {
                Object tok2 = readToken();
                if (tok2 instanceof Long && (Long) tok2 >= 0 && (Long) tok2 <= 0xffff) {
                    Object tok3 = readToken();
                    if (isKw(tok3, "R")) return new PRef((int) (long) (Long) tok, (int) (long) (Long) tok2);
                    if (isKw(tok3, "obj")) {
                        int[] old = objptr;
                        int[] ptr = {(int) (long) (Long) tok, (int) (long) (Long) tok2};
                        objptr = ptr;
                        Object obj = readObject();
                        if (!(obj instanceof PStream)) {
                            Object tok4 = readToken();
                            if (!isKw(tok4, "endobj")) throw new PdfError("missing endobj after indirect object definition");
                        }
                        objptr = old;
                        return new ObjDef(ptr, asObj(obj));
                    }
                    unreadToken(tok3);
                }
                unreadToken(tok2);
            }
            return tok;
        }

        private List<Object> readArray() {
            List<Object> x = new ArrayList<>();
            for (;;) {
                Object tok = readToken();
                if (isKw(tok, "]")) break;
                if (tok == EOF) throw new PdfError("unterminated array");
                if (isKw(tok, "endobj")) throw new PdfError("unterminated array");
                unreadToken(tok);
                x.add(asObj(readObject()));
            }
            return x;
        }

        private Object readDict() {
            Map<String, Object> x = new LinkedHashMap<>();
            for (;;) {
                Object tok = readToken();
                if (isKw(tok, ">>")) break;
                if (tok == EOF) throw new PdfError("unterminated dictionary");
                if (!(tok instanceof PName)) throw new PdfError("unexpected non-name key parsing dictionary");
                x.put(((PName) tok).n, asObj(readObject()));
            }
            Object tok = readToken();
            if (!isKw(tok, "stream")) {
                unreadToken(tok);
                return x;
            }
            int c = readByte();
            if (c == 13) {
                if (readByte() != 10) unreadByte();
            } else if (c != 10) {
                throw new PdfError("stream keyword not followed by newline");
            }
            return new PStream(x, objptr, pos);
        }
    }

    private static Object asObj(Object o) {
        if (o instanceof ObjDef || o == EOF || o instanceof PKeyword) throw new PdfError("unexpected token in object");
        return o;
    }

    static final class Xref {
        final int[] ptr;
        final boolean inStream;
        final int[] stream;
        final long offset;

        Xref(int[] ptr, boolean inStream, int[] stream, long offset) {
            this.ptr = ptr;
            this.inStream = inStream;
            this.stream = stream;
            this.offset = offset;
        }
    }

    static final Xref ZERO_XREF = new Xref(NO_PTR, false, NO_PTR, 0);

    private static boolean ptrEq(int[] a, int[] b) {
        return a[0] == b[0] && a[1] == b[1];
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asDict(Object o) {
        return o instanceof Map ? (Map<String, Object>) o : null;
    }

    @SuppressWarnings("unchecked")
    private static List<Object> asArr(Object o) {
        return o instanceof List ? (List<Object>) o : null;
    }

    /** digitorus Value: data + the pointer of the object that contains it. */
    final class Value {
        final int[] ptr;
        /** null = absent (TS undefined); NULL = PDF null. */
        final Object data;

        Value(int[] ptr, Object data) {
            this.ptr = ptr;
            this.data = data;
        }

        boolean isNull() {
            return data == null || data == NULL;
        }

        String kind() {
            Object d = data;
            if (d == null || d == NULL || d instanceof PRef) return "null";
            if (d instanceof Boolean) return "bool";
            if (d instanceof Long) return "int";
            if (d instanceof PReal) return "real";
            if (d instanceof PStr) return "string";
            if (d instanceof PName) return "name";
            if (d instanceof Map) return "dict";
            if (d instanceof List) return "array";
            return "stream";
        }

        private Map<String, Object> dict() {
            if (data instanceof Map) return asDict(data);
            if (data instanceof PStream) return ((PStream) data).hdr;
            return null;
        }

        Value key(String k) {
            Map<String, Object> d = dict();
            if (d == null) return new Value(NO_PTR, null);
            return resolve(ptr, d.get(k));
        }

        /** Byte order (Go sort.Strings; names are latin1 chars, so char order = byte order). */
        List<String> keys() {
            Map<String, Object> d = dict();
            if (d == null) return List.of();
            List<String> k = new ArrayList<>(d.keySet());
            k.sort(null);
            return k;
        }

        Value index(int i) {
            List<Object> d = asArr(data);
            if (d == null || i < 0 || i >= d.size()) return new Value(NO_PTR, null);
            return resolve(ptr, d.get(i));
        }

        int len() {
            List<Object> d = asArr(data);
            return d == null ? 0 : d.size();
        }

        String name() {
            return data instanceof PName ? ((PName) data).n : "";
        }

        long int64() {
            return data instanceof Long ? (Long) data : 0;
        }

        double float64() {
            if (data instanceof PReal) return ((PReal) data).v;
            if (data instanceof Long) return (double) (Long) data;
            return 0;
        }

        byte[] rawString() {
            return data instanceof PStr ? ((PStr) data).b : new byte[0];
        }

        /** The stream's /Length (int64; 0 when absent), without reading it. */
        long streamLength() {
            return key("Length").int64();
        }

        /** The decoded stream (digitorus Value.Reader). */
        byte[] streamData() {
            return streamData(MAX_STREAM);
        }

        /** The decoded stream, at most [limit] bytes after every filter (else PdfError). */
        byte[] streamData(int limit) {
            if (!(data instanceof PStream)) throw new PdfError("stream not present");
            PStream x = (PStream) data;
            byte[] cached = decoded.get(x);
            if (cached != null) {
                if (cached.length > limit) throw new PdfError("stream larger than allowed");
                return cached;
            }
            long n = key("Length").int64();
            if (n < 0 || x.offset + n > bytes.length) throw new PdfError("stream length beyond the file");
            if (n > limit) throw new PdfError("stream larger than allowed");
            charge(n); // the raw copy counts against the reader's work budget too
            byte[] out = Arrays.copyOfRange(bytes, x.offset, (int) (x.offset + n));
            Value filter = key("Filter");
            Value param = key("DecodeParms");
            switch (filter.kind()) {
                case "null":
                    break;
                case "name":
                    out = applyFilter(out, filter.name(), param, limit);
                    break;
                case "array":
                    for (int i = 0; i < filter.len(); i++) out = applyFilter(out, filter.index(i).name(), param.index(i), limit);
                    break;
                default:
                    throw new PdfError("unsupported filter");
            }
            if (out.length > limit) throw new PdfError("stream larger than allowed");
            if (decodedBytes + out.length <= MAX_CACHE_BYTES) {
                decoded.put(x, out);
                decodedBytes += out.length;
            }
            return out;
        }
    }

    private byte[] applyFilter(byte[] data, String name, Value param, int limit) {
        if (!name.equals("FlateDecode")) throw new PdfError("unknown filter " + name);
        byte[] out = zlibInflate(data, limit);
        Value pred = param.key("Predictor");
        if (pred.kind().equals("null")) return out;
        if (pred.int64() != 12) throw new PdfError("unknown predictor");
        long columns = param.key("Columns").int64();
        if (columns < 0 || columns > out.length) throw new PdfError("bad Columns");
        int row = (int) (1 + columns);
        byte[] hist = new byte[row];
        int rows = out.length / row;
        byte[] res = new byte[(int) (rows * columns)];
        for (int r = 0; r < rows; r++) {
            if (out[r * row] != 2) return Arrays.copyOf(res, (int) (r * columns));
            for (int i = 0; i < row; i++) hist[i] = (byte) (hist[i] + out[r * row + i]);
            System.arraycopy(hist, 1, res, (int) (r * columns), (int) columns);
        }
        return res;
    }

    /** TS zlibInflate: zlib header checked, raw deflate, adler32 NOT required, a truncated stream returns its prefix. */
    private byte[] zlibInflate(byte[] src, int limit) {
        if (src.length < 2) throw new PdfError("zlib: no header");
        int cmf = src[0] & 0xff;
        int flg = src[1] & 0xff;
        if ((cmf & 0x0f) != 8 || (cmf >> 4) > 7 || ((cmf << 8) | flg) % 31 != 0) throw new PdfError("zlib: bad header");
        if ((flg & 0x20) != 0) throw new PdfError("zlib: preset dictionary");
        Inflater inf = new Inflater(true);
        try {
            inf.setInput(src, 2, src.length - 2);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0) {
                    if (inf.needsInput() || inf.needsDictionary()) break; // truncated: the decoded prefix
                    continue;
                }
                if (out.size() + (long) n > Math.min(limit, MAX_STREAM)) throw new PdfError("inflate: size limit");
                charge(n);
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new PdfError("inflate: " + e.getMessage());
        } finally {
            inf.end();
        }
    }

    final byte[] bytes;
    /** digitorus xref (index = object number); null entries = the zero entry. */
    List<Xref> xref = new ArrayList<>();
    Map<String, Object> trailer = new LinkedHashMap<>();
    int[] trailerPtr = NO_PTR;
    private final Map<Long, Value> cache = new HashMap<>();
    private final Map<PStream, byte[]> decoded = new java.util.IdentityHashMap<>();
    private final Map<PStream, Map<Long, Long>> objStmIndexes = new java.util.IdentityHashMap<>();
    private long work;
    private long decodedBytes;

    /** Charges [n] bytes of copying / inflating to the reader's total work budget. */
    private void charge(long n) {
        work += n;
        if (work > MAX_WORK_TOTAL) throw new PdfError("PDF work budget exceeded");
    }

    Xref xrefAt(int i) {
        Xref x = xref.get(i);
        return x == null ? ZERO_XREF : x;
    }

    DReader(byte[] b) {
        this.bytes = b;
        boolean ok17 = b.length >= 8 && startsWith(b, "%PDF-1.") && b[7] >= '0' && b[7] <= '7';
        boolean ok20 = b.length >= 8 && startsWith(b, "%PDF-2.") && b[7] == '0';
        if (!ok17 && !ok20) throw new PdfError("not a PDF file: invalid header");
        int startxrefPos = findStartXref(b);
        Lexer lx = new Lexer(b, startxrefPos, false);
        if (!isKw(lx.readToken(), "startxref")) throw new PdfError("malformed PDF file: missing startxref");
        Object sx = lx.readToken();
        if (!(sx instanceof Long)) throw new PdfError("malformed PDF file: startxref not followed by integer");
        long startXref = (Long) sx;
        if (startXref < 0 || startXref >= b.length) throw new PdfError("bad startxref");
        Lexer x = new Lexer(b, (int) startXref, false);
        Object tok = x.readToken();
        if (isKw(tok, "xref")) {
            readXrefTable(x);
        } else if (tok instanceof Long) {
            x.unreadToken(tok);
            readXrefStream(x);
        } else {
            throw new PdfError("malformed PDF: cross-reference table not found");
        }
    }

    private static boolean startsWith(byte[] b, String p) {
        if (b.length < p.length()) return false;
        for (int i = 0; i < p.length(); i++) if (b[i] != (byte) p.charAt(i)) return false;
        return true;
    }

    Value trailerValue() {
        return new Value(trailerPtr, trailer);
    }

    private static Long asLong(Object o) {
        return o instanceof Long ? (Long) o : null;
    }

    private void readXrefStream(Lexer b) {
        Object def0 = b.readObject();
        if (!(def0 instanceof ObjDef) || !(((ObjDef) def0).obj instanceof PStream)) throw new PdfError("malformed PDF: cross-reference table not found");
        ObjDef def = (ObjDef) def0;
        PStream strm = (PStream) def.obj;
        Object type = strm.hdr.get("Type");
        if (!(type instanceof PName) || !((PName) type).n.equals("XRef")) throw new PdfError("malformed PDF: xref stream does not have type XRef");
        Long sizeObj = asLong(strm.hdr.get("Size"));
        if (sizeObj == null) throw new PdfError("malformed PDF: xref stream missing Size");
        long size = sizeObj;
        if (size < 0 || size > 1 << 24) throw new PdfError("bad xref Size");
        List<Xref> table = new ArrayList<>(java.util.Collections.nCopies((int) Math.min(size, MAX_XREF_IDS), (Xref) null));
        readXrefStreamData(strm, table, size);
        Set<Long> seen = new HashSet<>();
        Object prevoff = strm.hdr.get("Prev");
        while (prevoff != null && prevoff != NULL) {
            if (!(prevoff instanceof Long)) throw new PdfError("malformed PDF: xref Prev is not integer");
            long off = (Long) prevoff;
            if (!seen.add(off)) throw new PdfError("malformed PDF: xref Prev loop detected");
            if (seen.size() >= MAX_XREF_SECTIONS) throw new PdfError("too many xref sections");
            if (off < 0 || off >= bytes.length) throw new PdfError("bad xref Prev");
            Object pd = new Lexer(bytes, (int) off, false).readObject();
            if (!(pd instanceof ObjDef) || !(((ObjDef) pd).obj instanceof PStream)) throw new PdfError("malformed PDF: xref prev stream not found");
            PStream ps = (PStream) ((ObjDef) pd).obj;
            prevoff = ps.hdr.get("Prev");
            Value prev = new Value(NO_PTR, ps);
            if (!prev.key("Type").name().equals("XRef")) throw new PdfError("malformed PDF: xref prev stream does not have type XRef");
            long psize = prev.key("Size").int64();
            if (psize > size) throw new PdfError("malformed PDF: xref prev stream larger than last stream");
            readXrefStreamData(ps, table, psize);
        }
        this.xref = table;
        this.trailerPtr = def.ptr;
        this.trailer = strm.hdr;
    }

    private void readXrefStreamData(PStream strm, List<Xref> table, long size) {
        List<Object> index = asArr(strm.hdr.get("Index"));
        if (index == null) index = List.of(0L, size);
        if (index.size() % 2 != 0) throw new PdfError("invalid Index array");
        List<Object> ww = asArr(strm.hdr.get("W"));
        if (ww == null) throw new PdfError("xref stream missing W array");
        int[] w = new int[ww.size()];
        int wtotal = 0;
        for (int i = 0; i < w.length; i++) {
            Long v = asLong(ww.get(i));
            if (v == null || v < 0 || v > 8) throw new PdfError("invalid W array");
            w[i] = (int) (long) v;
            wtotal += w[i];
        }
        if (w.length < 3) throw new PdfError("invalid W array");
        if (wtotal <= 0) throw new PdfError("invalid W array: empty rows"); // else /Index could loop without reading
        byte[] data = new Value(NO_PTR, strm).streamData();
        int p = 0;
        for (int k = 0; k + 1 < index.size(); k += 2) {
            Long s = asLong(index.get(k));
            Long n = asLong(index.get(k + 1));
            if (s == null || n == null) throw new PdfError("malformed Index pair");
            long start = s;
            for (long i = 0; i < n; i++) {
                if (p + wtotal > data.length) throw new PdfError("error reading xref stream: EOF");
                int base = p;
                long v1 = dec(data, p, w[0]);
                p += w[0];
                if (w[0] == 0) v1 = 1;
                long v2 = dec(data, p, w[1]);
                p += w[1];
                long v3 = dec(data, p, w[2]);
                p = base + wtotal;
                long x = start + i;
                if (x < 0) throw new PdfError("xref stream: index out of range");
                // Never grow the table past 2^21 ids (writer guard, PdfReader): such rows are ignored.
                if (x >= MAX_XREF_IDS) continue;
                if (x >= table.size()) {
                    // Go: append(table[:cap], …) grows by the next row only; anything further is out of range.
                    if (x != table.size()) throw new PdfError("xref stream: index out of range");
                    table.add(null);
                }
                int xi = (int) x;
                if (table.get(xi) != null && !ptrEq(table.get(xi).ptr, NO_PTR)) continue;
                if (v1 == 0) table.set(xi, new Xref(new int[] {0, 65535}, false, NO_PTR, 0));
                else if (v1 == 1) table.set(xi, new Xref(new int[] {xi, (int) (v3 & 0xffff)}, false, NO_PTR, v2));
                else if (v1 == 2) table.set(xi, new Xref(new int[] {xi, 0}, true, new int[] {(int) v2, 0}, v3));
            }
        }
    }

    /** Big-endian unsigned (JS number arithmetic; W ≤ 8 so up to 2^64 — kept as a double-safe long like TS). */
    private static long dec(byte[] d, int p, int n) {
        double x = 0;
        for (int i = 0; i < n; i++) x = x * 256 + (d[p + i] & 0xff);
        return x >= 9.223372036854776E18 ? Long.MAX_VALUE : (long) x;
    }

    private void readXrefTable(Lexer b) {
        List<Xref> table = new ArrayList<>();
        readXrefTableData(b, table);
        Object trailer0 = b.readObject();
        Map<String, Object> tr = asDict(trailer0);
        if (tr == null) throw new PdfError("malformed PDF: xref table not followed by trailer dictionary");
        Set<Long> seen = new HashSet<>();
        Object prevoff = tr.get("Prev");
        while (prevoff != null && prevoff != NULL) {
            if (!(prevoff instanceof Long)) throw new PdfError("malformed PDF: xref Prev is not integer");
            long off = (Long) prevoff;
            if (!seen.add(off)) throw new PdfError("malformed PDF: xref Prev loop detected");
            if (seen.size() >= MAX_XREF_SECTIONS) throw new PdfError("too many xref sections");
            if (off < 0 || off >= bytes.length) throw new PdfError("bad xref Prev");
            Lexer pb = new Lexer(bytes, (int) off, false);
            if (!isKw(pb.readToken(), "xref")) throw new PdfError("malformed PDF: xref Prev does not point to xref");
            readXrefTableData(pb, table);
            Map<String, Object> t2 = asDict(pb.readObject());
            if (t2 == null) throw new PdfError("malformed PDF: xref Prev table not followed by trailer dictionary");
            prevoff = t2.get("Prev");
        }
        Long size = asLong(tr.get("Size"));
        if (size == null) throw new PdfError("malformed PDF: trailer missing /Size entry");
        if (size < table.size()) table = new ArrayList<>(table.subList(0, (int) Math.max(0, size)));
        this.xref = table;
        this.trailer = tr;
        this.trailerPtr = NO_PTR;
    }

    private void readXrefTableData(Lexer b, List<Xref> table) {
        for (;;) {
            Object tok = b.readToken();
            if (isKw(tok, "trailer")) break;
            Object n = b.readToken();
            if (!(tok instanceof Long) || !(n instanceof Long)) throw new PdfError("malformed xref table");
            long start = (Long) tok;
            long count = (Long) n;
            if (start < 0 || count < 0 || start + count > 1 << 24) throw new PdfError("malformed xref table");
            for (long i = 0; i < count; i++) {
                Object off = b.readToken();
                Object gen = b.readToken();
                Object alloc = b.readToken();
                if (!(off instanceof Long) || !(gen instanceof Long) || !(alloc instanceof PKeyword)
                    || !(((PKeyword) alloc).k.equals("f") || ((PKeyword) alloc).k.equals("n"))) {
                    throw new PdfError("malformed xref table");
                }
                if (start + i >= MAX_XREF_IDS) continue; // ids beyond 2^21 ignored (no table growth)
                int x = (int) (start + i);
                while (table.size() <= x) table.add(null);
                Xref cur = table.get(x);
                if (((PKeyword) alloc).k.equals("n") && (cur == null || cur.offset == 0)) {
                    table.set(x, new Xref(new int[] {x, (int) ((Long) gen & 0xffff)}, false, NO_PTR, (Long) off));
                }
            }
        }
    }

    /** digitorus resolve(parent, x). */
    Value resolve(int[] parent, Object x) {
        if (x instanceof PRef) {
            PRef r = (PRef) x;
            long key = ((long) r.id << 16) | r.gen;
            Value hit = cache.get(key);
            if (hit != null) return hit;
            Value v = load(r);
            cache.put(key, v);
            return v;
        }
        return new Value(parent, x);
    }

    private Value load(PRef ptr) {
        if (ptr.id < 0 || ptr.id >= xref.size()) return new Value(NO_PTR, null);
        Xref xr = xrefAt(ptr.id);
        if (xr.ptr[0] != ptr.id || xr.ptr[1] != ptr.gen || (!xr.inStream && xr.offset == 0)) return new Value(NO_PTR, null);
        int[] p = {ptr.id, ptr.gen};
        Object x = null;
        if (xr.inStream) {
            Value strm = resolve(p, new PRef(xr.stream[0], xr.stream[1]));
            for (int guard = 0; ; guard++) {
                if (guard > 64) throw new PdfError("object stream /Extends chain too long");
                if (!strm.kind().equals("stream")) throw new PdfError("not a stream");
                if (!strm.key("Type").name().equals("ObjStm")) throw new PdfError("not an object stream");
                long n = strm.key("N").int64();
                long first = strm.key("First").int64();
                if (first == 0) throw new PdfError("missing First");
                byte[] data = strm.streamData();
                Map<Long, Long> index = objStmIndex((PStream) strm.data, data, n);
                Object found = null;
                boolean ok = false;
                Long o = index.get((long) ptr.id & 0xffffffffL);
                if (o != null) {
                    Lexer b = new Lexer(data, 0, true);
                    long at = first + o;
                    b.pos = at < 0 || at > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) at;
                    found = asObj(b.readObject());
                    ok = true;
                }
                if (ok) {
                    x = found;
                    break;
                }
                Value ext = strm.key("Extends");
                if (!ext.kind().equals("stream")) throw new PdfError("cannot find object in stream");
                strm = ext;
            }
        } else {
            if (xr.offset < 0 || xr.offset > Integer.MAX_VALUE) throw new PdfError("bad offset");
            Lexer b = new Lexer(bytes, (int) xr.offset, false);
            Object def = b.readObject();
            if (!(def instanceof ObjDef)) throw new PdfError("loading object: not an objdef");
            if (!ptrEq(((ObjDef) def).ptr, p)) throw new PdfError("loading object: found another object");
            x = ((ObjDef) def).obj;
        }
        return new Value(p, x);
    }

    /**
     * The object stream header (id → offset of the FIRST pair with that id, like the reference's linear scan), read once
     * per stream: at most N pairs, stopping at the end of the data.
     */
    private Map<Long, Long> objStmIndex(PStream s, byte[] data, long n) {
        Map<Long, Long> idx = objStmIndexes.get(s);
        if (idx != null) return idx;
        idx = new HashMap<>();
        Lexer b = new Lexer(data, 0, true);
        try {
            for (long i = 0; i < n; i++) {
                Object id = b.readToken();
                Object off = b.readToken();
                if (id == EOF || off == EOF) break;
                long idn = id instanceof Long ? ((Long) id) & 0xffffffffL : 0;
                idx.putIfAbsent(idn, off instanceof Long ? (Long) off : 0L);
            }
        } catch (PdfError e) {
            // The reference throws only when it reaches this pair; ids after it are "not found" (→ /Extends → error).
        }
        objStmIndexes.put(s, idx);
        return idx;
    }

    /** digitorus NewReader's %%EOF / startxref search (TS findStartXref — the single-pass equivalent). */
    private static int findStartXref(byte[] b) {
        int end = b.length;
        int hi = end;
        while (hi > 0 && (b[hi - 1] == 10 || b[hi - 1] == 13 || b[hi - 1] == 9 || b[hi - 1] == 32)) hi--;
        int idx = -1;
        for (int i = hi - 5; i >= 0; i--) {
            if (b[i] == '%' && b[i + 1] == '%' && b[i + 2] == 'E' && b[i + 3] == 'O' && b[i + 4] == 'F') {
                idx = i;
                break;
            }
        }
        if (idx < 0 || 200L * ((end - idx) / 200 + 1) > end) throw new PdfError("not a PDF file: missing %%EOF");
        int eofEnd = idx + 5;
        int winStart = eofEnd - 200;
        if (winStart < 0) throw new PdfError("malformed PDF file: missing final startxref");
        int i = findLastLine(b, winStart, eofEnd, "startxref");
        if (i < 0) throw new PdfError("malformed PDF file: missing final startxref");
        return winStart + i;
    }

    private static int findLastLine(byte[] b, int from, int to, String s) {
        String str = new String(b, from, to - from, StandardCharsets.ISO_8859_1);
        int len = to - from;
        int max = len;
        for (;;) {
            int i = str.lastIndexOf(s, max - s.length());
            if (i <= 0 || i + s.length() >= len) return -1;
            int before = b[from + i - 1];
            int after = b[from + i + s.length()];
            if ((before == 10 || before == 13) && (after == 10 || after == 13)) return i;
            max = i;
        }
    }
}
