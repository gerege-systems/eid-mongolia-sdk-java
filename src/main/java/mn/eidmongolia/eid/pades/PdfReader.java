package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Cross-reference structure of a PDF (classic tables, xref streams, hybrid files, object streams) + indirect object
 * resolution (the digitorus/pdf subset the Go writer uses). Reading compressed input streams uses [Inflater] — only
 * WRITING is uncompressed (cross-SDK byte identity). Not thread-safe (per-call instances only).
 */
final class PdfReader {
    /** Offset entry ([stream] < 0) or compressed entry (object [index] of object stream [stream]). */
    static final class XrefEntry {
        final boolean compressed;
        final int off;
        final int gen;
        final int stream;
        final int index;

        private XrefEntry(boolean compressed, int off, int gen, int stream, int index) {
            this.compressed = compressed;
            this.off = off;
            this.gen = gen;
            this.stream = stream;
            this.index = index;
        }

        static XrefEntry offset(int off, int gen) {
            return new XrefEntry(false, off, gen, -1, -1);
        }

        static XrefEntry inStream(int stream, int index) {
            return new XrefEntry(true, 0, 0, stream, index);
        }
    }

    private static final class ObjStm {
        final int first;
        final List<int[]> offsets;
        final byte[] data;

        ObjStm(int first, List<int[]> offsets, byte[] data) {
            this.first = first;
            this.offsets = offsets;
            this.data = data;
        }
    }

    final byte[] bytes;
    /** Header version, e.g. "1.3". */
    final String version;
    /** Latest trailer (for an xref stream: its dictionary). */
    final PdfDict trailer;
    /** `startxref` of the file — the new revision's /Prev. */
    final int startXref;
    /** The latest xref section is a stream (the new revision writes the same kind). */
    final boolean xrefIsStream;
    final Map<Integer, XrefEntry> xref;
    private final Map<PdfRef, PdfObj> cache = new HashMap<>();
    /** Objects being parsed right now (re-entry guard, see [obj]). */
    private final Set<PdfRef> loading = new HashSet<>();
    private static final int MAX_LOADING = 64;
    private final Map<Integer, ObjStm> objStmCache = new HashMap<>();

    private PdfReader(byte[] bytes, String version, PdfDict trailer, int startXref, boolean xrefIsStream, Map<Integer, XrefEntry> xref) {
        this.bytes = bytes;
        this.version = version;
        this.trailer = trailer;
        this.startXref = startXref;
        this.xrefIsStream = xrefIsStream;
        this.xref = xref;
    }

    int maxObjectId() {
        int m = 0;
        for (int k : xref.keySet()) m = Math.max(m, k);
        return m;
    }

    /** Object numbers in ascending order (Go digitorus `Xref()` iteration order). */
    List<Integer> objectIds() {
        List<Integer> l = new ArrayList<>(xref.keySet());
        Collections.sort(l);
        return l;
    }

    private static final class Section {
        final PdfDict dict;
        final boolean isStream;
        final Map<Integer, XrefEntry> entries;

        Section(PdfDict dict, boolean isStream, Map<Integer, XrefEntry> entries) {
            this.dict = dict;
            this.isStream = isStream;
            this.entries = entries;
        }
    }

    static PdfReader open(byte[] data) {
        String version = headerVersion(data);
        Integer sx = findStartXref(data);
        if (sx == null) throw new PdfException("startxref not found");
        Set<Integer> seen = new HashSet<>();
        Integer offset = sx;
        Section first = null;
        Map<Integer, XrefEntry> entries = new HashMap<>();
        while (offset != null) {
            int off = offset;
            if (seen.contains(off)) break;
            if (seen.size() >= 512 || off < 0 || off >= data.length) throw new PdfException("bad xref offset");
            seen.add(off);
            Section sec = readSection(data, off);
            if (first == null) first = sec;
            Map<Integer, XrefEntry> merged = new HashMap<>(sec.entries);
            if (!sec.isStream) {
                Long stmL = sec.dict.get("XRefStm").asLong();
                if (stmL != null) {
                    int stm = (int) (long) stmL;
                    if (!seen.contains(stm)) {
                        seen.add(stm);
                        try {
                            Map<Integer, XrefEntry> extra = readSection(data, stm).entries;
                            for (Map.Entry<Integer, XrefEntry> e : extra.entrySet()) merged.putIfAbsent(e.getKey(), e.getValue());
                        } catch (Exception e) {
                            // ignored, as digitorus
                        }
                    }
                }
            }
            for (Map.Entry<Integer, XrefEntry> e : merged.entrySet()) entries.putIfAbsent(e.getKey(), e.getValue());
            Long prev = sec.dict.get("Prev").asLong();
            offset = prev == null ? null : (int) (long) prev;
        }
        if (first == null) throw new PdfException("no xref");
        return new PdfReader(data, version, first.dict, sx, first.isStream, entries);
    }

    static String headerVersion(byte[] b) {
        int limit = Math.min(b.length, 1024);
        int at = indexOf(b, Text.latin1("%PDF-"), 0, limit);
        if (at < 0) return "";
        int i = at + 5;
        StringBuilder sb = new StringBuilder();
        while (i < limit && ((b[i] >= '0' && b[i] <= '9') || b[i] == '.')) sb.append((char) b[i++]);
        return sb.toString();
    }

    static Integer findStartXref(byte[] b) {
        byte[] key = Text.latin1("startxref");
        int from = Math.max(0, b.length - 2048);
        for (int i = b.length - key.length; i >= from; i--) {
            if (regionEquals(b, i, key)) return PdfLexer.toInt(new PdfLexer(b, i + key.length).word());
        }
        return null;
    }

    static int indexOf(byte[] b, byte[] key, int from) {
        return indexOf(b, key, from, b.length);
    }

    static int indexOf(byte[] b, byte[] key, int from, int to) {
        for (int i = Math.max(from, 0); i + key.length <= to; i++) {
            if (regionEquals(b, i, key)) return i;
        }
        return -1;
    }

    private static boolean regionEquals(byte[] b, int at, byte[] key) {
        if (at < 0 || at + key.length > b.length) return false;
        for (int k = 0; k < key.length; k++) if (b[at + k] != key[k]) return false;
        return true;
    }

    private static Section readSection(byte[] b, int off) {
        PdfLexer lx = new PdfLexer(b, off);
        lx.skipWhite();
        Object[] pw = lx.peekWord(lx.pos);
        if (pw != null && pw[0].equals("xref")) {
            lx.pos = (Integer) pw[1];
            Map<Integer, XrefEntry> out = new HashMap<>();
            while (true) {
                lx.skipWhite();
                Object[] w2 = lx.peekWord(lx.pos);
                if (w2 == null) throw new PdfException("bad xref table");
                if (w2[0].equals("trailer")) {
                    lx.word();
                    break;
                }
                Integer start = PdfLexer.toInt(lx.word());
                Integer count = PdfLexer.toInt(lx.word());
                if (start == null || count == null || count < 0 || count >= (1 << 23)) throw new PdfException("bad xref subsection");
                for (int k = 0; k < count; k++) {
                    Integer o = PdfLexer.toInt(lx.word());
                    Integer g = PdfLexer.toInt(lx.word());
                    String t = lx.word();
                    if (o == null || g == null || t == null) throw new PdfException("bad xref entry");
                    int id = start + k;
                    if (t.equals("n") && !out.containsKey(id) && o > 0) out.put(id, XrefEntry.offset(o, g));
                }
            }
            PdfObj tr = lx.parseObject();
            if (!(tr instanceof PdfObj.Dict)) throw new PdfException("bad trailer");
            return new Section(((PdfObj.Dict) tr).d(), false, out);
        }
        PdfReader bare = new PdfReader(b, "", new PdfDict(), 0, false, Collections.emptyMap());
        PdfObj obj = bare.parseIndirect(off, null);
        if (!(obj instanceof PdfObj.Stream) || !"XRef".equals(((PdfObj.Stream) obj).d().get("Type").name())) {
            throw new PdfException("xref stream expected");
        }
        PdfDict d = ((PdfObj.Stream) obj).d();
        byte[] raw = bare.decodedStream(obj);
        List<PdfObj> wa = d.get("W").array();
        Long size = d.get("Size").asLong();
        List<Integer> w = null;
        if (wa != null) {
            w = new ArrayList<>();
            for (PdfObj x : wa) {
                Long v = x.asLong();
                if (v != null) w.add((int) (long) v);
            }
        }
        boolean badW = w == null || w.size() != 3;
        if (!badW) for (int x : w) if (x < 0 || x > 8) badW = true;
        if (badW || size == null) throw new PdfException("bad xref stream");
        List<Integer> index = new ArrayList<>();
        List<PdfObj> ia = d.get("Index").array();
        if (ia != null) {
            for (PdfObj x : ia) {
                Long v = x.asLong();
                if (v != null) index.add((int) (long) v);
            }
        } else {
            index.add(0);
            index.add((int) (long) size);
        }
        if (index.size() % 2 != 0) index.remove(index.size() - 1);
        int rowLen = w.get(0) + w.get(1) + w.get(2);
        if (rowLen <= 0) throw new PdfException("bad xref stream /W");
        Map<Integer, XrefEntry> out = new HashMap<>();
        int[] p = {0};
        for (int pair = 0; pair < index.size(); pair += 2) {
            int start = index.get(pair);
            int count = index.get(pair + 1);
            for (int k = 0; k < count; k++) {
                if (p[0] + rowLen > raw.length) break;
                int type = field(raw, p, w.get(0), 1);
                int f2 = field(raw, p, w.get(1), 0);
                int f3 = field(raw, p, w.get(2), 0);
                long id64 = (long) start + k;
                // PRECHECKS #2b caps /Size at 2^21: a valid id is below it. A hostile /Index count (e.g. [0 67108864]
                // over a small zlib bomb) would otherwise allocate one map entry per row.
                if (id64 < 0 || id64 >= Structure.MAX_XREF_SIZE) continue;
                int id = (int) id64;
                if (out.containsKey(id)) continue;
                if (type == 1) {
                    if (f2 > 0) out.put(id, XrefEntry.offset(f2, f3));
                } else if (type == 2) {
                    out.put(id, XrefEntry.inStream(f2, f3));
                }
            }
        }
        return new Section(d, true, out);
    }

    private static int field(byte[] raw, int[] p, int n, int def) {
        if (n <= 0) return def;
        int v = 0;
        for (int k = 0; k < n; k++) v = (v << 8) | (raw[p[0]++] & 0xff);
        return v;
    }

    private static boolean endstreamFollows(byte[] b, int p) {
        return "endstream".equals(new PdfLexer(b, p).word());
    }

    static byte[] inflate(byte[] input) {
        return inflate(input, 64 << 20);
    }

    static byte[] inflate(byte[] input, int limit) {
        Inflater inf = new Inflater();
        try {
            inf.setInput(input);
            ByteArrayOutputStream out = new ByteArrayOutputStream(input.length * 2);
            byte[] buf = new byte[64 << 10];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) break; // truncated: keep what we have
                out.write(buf, 0, n);
                if (out.size() > limit) throw new PdfException("FlateDecode output too large");
            }
            return out.toByteArray();
        } catch (DataFormatException e) {
            throw new PdfException("FlateDecode failed");
        } finally {
            inf.end();
        }
    }

    private static byte[] unpredict(byte[] data, PdfDict p) {
        Long pr = p.get("Predictor").asLong();
        int predictor = pr == null ? 1 : (int) (long) pr;
        if (predictor < 10) {
            if (predictor == 1) return data;
            throw new PdfException("unsupported predictor " + predictor);
        }
        Long co = p.get("Colors").asLong();
        Long bp = p.get("BitsPerComponent").asLong();
        Long cl = p.get("Columns").asLong();
        int colors = co == null ? 1 : (int) (long) co;
        int bpc = bp == null ? 8 : (int) (long) bp;
        int columns = cl == null ? 1 : (int) (long) cl;
        int bpp = Math.max(1, colors * bpc / 8);
        int rowLen = (colors * bpc * columns + 7) / 8;
        if (rowLen <= 0) throw new PdfException("bad predictor parameters");
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
        int[] prev = new int[rowLen];
        int i = 0;
        while (i + 1 + rowLen <= data.length) {
            int type = data[i] & 0xff;
            int[] row = new int[rowLen];
            for (int x = 0; x < rowLen; x++) row[x] = data[i + 1 + x] & 0xff;
            for (int x = 0; x < rowLen; x++) {
                int a = x >= bpp ? row[x - bpp] : 0;
                int bb = prev[x];
                int c = x >= bpp ? prev[x - bpp] : 0;
                int add;
                switch (type) {
                    case 0: add = 0; break;
                    case 1: add = a; break;
                    case 2: add = bb; break;
                    case 3: add = (a + bb) / 2; break;
                    case 4: {
                        int pp = a + bb - c;
                        int pa = Math.abs(pp - a);
                        int pb = Math.abs(pp - bb);
                        int pc = Math.abs(pp - c);
                        add = pa <= pb && pa <= pc ? a : pb <= pc ? bb : c;
                        break;
                    }
                    default:
                        throw new PdfException("bad PNG predictor row");
                }
                row[x] = (row[x] + add) & 0xff;
            }
            for (int v : row) out.write(v);
            prev = row;
            i += 1 + rowLen;
        }
        return out.toByteArray();
    }

    /** The object a reference points to; [PdfObj.NULL] when it does not exist (§7.3.10). */
    PdfObj obj(PdfRef ref) {
        PdfObj hit = cache.get(ref);
        if (hit != null) return hit;
        XrefEntry entry = xref.get(ref.id());
        if (entry == null) return PdfObj.NULL;
        // A stream's /Length (or its object stream) may refer back to an object still being parsed — `3 0 obj
        // <</Length 3 0 R>>` recursed until StackOverflowError (an Error, past every catch). Re-entry and deep chains
        // fail as PdfException instead (the /Length lookup then falls back to scanning for endstream, like Go's lazy one).
        if (loading.size() >= MAX_LOADING || !loading.add(ref)) throw new PdfException("object " + ref.id() + " refers to itself");
        PdfObj o;
        try {
            if (!entry.compressed) {
                if (entry.gen != ref.gen()) return PdfObj.NULL;
                o = parseIndirect(entry.off, ref.id());
            } else {
                if (ref.gen() != 0) return PdfObj.NULL;
                o = objectFromStream(entry.stream, entry.index, ref.id());
            }
        } finally {
            loading.remove(ref);
        }
        cache.put(ref, o);
        return o;
    }

    /** Follows references (bounded). */
    PdfObj resolve(PdfObj o) {
        PdfObj cur = o;
        int n = 0;
        while (cur instanceof PdfObj.Ref) {
            if (++n >= 16) throw new PdfException("reference loop");
            cur = obj(((PdfObj.Ref) cur).r());
        }
        return cur;
    }

    PdfObj get(PdfDict d, String key) {
        return resolve(d.get(key));
    }

    PdfObj parseIndirect(int off, Integer id) {
        if (off < 0 || off >= bytes.length) throw new PdfException("object offset out of range");
        PdfLexer lx = new PdfLexer(bytes, off);
        Integer n = PdfLexer.toInt(lx.word());
        if (n == null || PdfLexer.toInt(lx.word()) == null) throw new PdfException("bad object header at " + off);
        if (id != null && !n.equals(id)) throw new PdfException("object " + id + " not at its xref offset");
        lx.expect("obj");
        PdfObj o = lx.parseObject();
        if (!(o instanceof PdfObj.Dict)) return o;
        PdfDict d = ((PdfObj.Dict) o).d();
        lx.skipWhite();
        Object[] pw = lx.peekWord(lx.pos);
        if (pw == null || !pw[0].equals("stream")) return o;
        int start = (Integer) pw[1];
        if (start < bytes.length && bytes[start] == 0x0D) start++;
        if (start < bytes.length && bytes[start] == 0x0A) start++;
        int length = -1;
        PdfObj lenObj = d.get("Length");
        Long direct = lenObj.asLong();
        if (direct != null) {
            length = (int) (long) direct;
        } else if (lenObj instanceof PdfObj.Ref) {
            try {
                Long v = resolve(lenObj).asLong();
                if (v != null) length = (int) (long) v;
            } catch (Exception e) {
                // fall back to scanning for endstream
            }
        }
        if (length >= 0 && (long) start + length <= bytes.length && endstreamFollows(bytes, start + length)) {
            return new PdfObj.Stream(d, start, start + length);
        }
        int r = indexOf(bytes, Text.latin1("endstream"), start);
        if (r < 0) throw new PdfException("endstream not found");
        int e = r;
        if (e > start && bytes[e - 1] == 0x0A) e--;
        if (e > start && bytes[e - 1] == 0x0D) e--;
        return new PdfObj.Stream(d, start, e);
    }

    /**
     * The dictionary of object [id] at [off] without resolving anything (no /Length lookup) and whether a stream follows
     * — for the object-stream graph check ([Structure]). null when it does not parse. Returns {PdfDict, Boolean}.
     */
    Object[] rawHeader(int off, int id) {
        try {
            if (off < 0 || off >= bytes.length) return null;
            PdfLexer lx = new PdfLexer(bytes, off);
            Integer n = PdfLexer.toInt(lx.word());
            if (n == null || n != id || PdfLexer.toInt(lx.word()) == null) return null;
            lx.expect("obj");
            PdfObj o = lx.parseObject();
            if (!(o instanceof PdfObj.Dict)) return null;
            lx.skipWhite();
            Object[] pw = lx.peekWord(lx.pos);
            return new Object[] {((PdfObj.Dict) o).d(), pw != null && pw[0].equals("stream")};
        } catch (Exception e) {
            return null;
        }
    }

    private PdfObj objectFromStream(int stm, int index, int id) {
        ObjStm entry = objStmCache.get(stm);
        if (entry == null) {
            PdfObj s = obj(new PdfRef(stm, 0));
            PdfDict sd = s.dict();
            Long n = sd == null ? null : sd.get("N").asLong();
            Long first = sd == null ? null : sd.get("First").asLong();
            if (!(s instanceof PdfObj.Stream) || !"ObjStm".equals(sd.get("Type").name()) || n == null || first == null || n < 0
                || n >= (1 << 20)) {
                throw new PdfException("bad object stream " + stm);
            }
            byte[] data = decodedStream(s);
            PdfLexer lx = new PdfLexer(data);
            List<int[]> offsets = new ArrayList<>();
            for (long k = 0; k < n; k++) {
                Integer oid = PdfLexer.toInt(lx.word());
                Integer o = PdfLexer.toInt(lx.word());
                if (oid == null || o == null) throw new PdfException("bad object stream header");
                offsets.add(new int[] {oid, o});
            }
            entry = new ObjStm((int) (long) first, offsets, data);
            objStmCache.put(stm, entry);
        }
        if (index < 0 || index >= entry.offsets.size() || entry.offsets.get(index)[0] != id) {
            throw new PdfException("object " + id + " not in object stream " + stm);
        }
        return new PdfLexer(entry.data, entry.first + entry.offsets.get(index)[1]).parseObject();
    }

    /** Decoded data of a stream (FlateDecode with PNG predictors, or unfiltered). */
    byte[] decodedStream(PdfObj s) {
        if (!(s instanceof PdfObj.Stream)) throw new PdfException("not a stream");
        PdfObj.Stream st = (PdfObj.Stream) s;
        byte[] data = Arrays.copyOfRange(bytes, st.start(), st.end());
        PdfObj f = resolve(st.d().get("Filter"));
        List<PdfObj> filters;
        if (f.isNull()) filters = Collections.emptyList();
        else if (f instanceof PdfObj.Name) filters = Collections.singletonList(f);
        else if (f instanceof PdfObj.Arr) filters = ((PdfObj.Arr) f).items();
        else throw new PdfException("bad /Filter");
        PdfObj pa = resolve(st.d().get("DecodeParms"));
        List<PdfObj> parms;
        if (pa instanceof PdfObj.Arr) parms = ((PdfObj.Arr) pa).items();
        else if (pa instanceof PdfObj.Dict) parms = Collections.singletonList(pa);
        else parms = Collections.emptyList();
        for (int i = 0; i < filters.size(); i++) {
            String fn = filters.get(i).name();
            if (!"FlateDecode".equals(fn) && !"Fl".equals(fn)) throw new PdfException("unsupported filter " + fn);
            data = inflate(data);
            if (i < parms.size()) {
                PdfDict pd = resolve(parms.get(i)).dict();
                if (pd != null) data = unpredict(data, pd);
            }
        }
        return data;
    }
}
