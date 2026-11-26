package mn.eidmongolia.eid.pades.validate;

import static mn.eidmongolia.eid.pades.validate.PdfObjects.ENT_COMP;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ENT_USE;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.FREE;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.MAX_OBJECT_NUMBER;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.MAX_XREF_SECTIONS;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.allGapSpace;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.arr;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.dget;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ent;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ifaceEq;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.inUse;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isArr;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isDict;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isDigit;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isInt;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.useEnt;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.pades.validate.PdfObjects.CachedObj;
import mn.eidmongolia.eid.pades.validate.PdfObjects.ObjStm;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PName;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PRef;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStream;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PdfBudget;
import mn.eidmongolia.eid.pades.validate.PdfObjects.XrefEnt;
import mn.eidmongolia.eid.pades.validate.PdfObjects.XrefSection;

/** One state of the document (its first len bytes): the merged xref chain and its objects (TS pdfobj.ts PdfView). */
final class PdfView {
    private static final Pattern DIGITS = Pattern.compile("[0-9]+");

    final byte[] b;
    final int len;
    final PdfBudget budget;
    final List<XrefSection> sections = new ArrayList<>();
    final Map<Integer, XrefEnt> xref = new LinkedHashMap<>();
    Map<String, Object> trailer = new LinkedHashMap<>();
    private final Map<Integer, Object> objs = new LinkedHashMap<>();
    private boolean inLength;
    private boolean usedLength;
    private Map<Integer, List<Integer>> refs;

    PdfView(byte[] b, int len, PdfBudget budget) {
        this.b = b;
        this.len = len;
        this.budget = budget;
    }

    PdfParser parser(int pos) {
        return new PdfParser(b, len, pos, budget);
    }

    XrefSection section(int off) {
        PdfParser p = parser(off);
        p.skipGap();
        XrefSection sec = new XrefSection(off, p.pos);
        if (p.pos >= len || ((b[p.pos] & 0xff) != 'x' && !isDigit(b[p.pos] & 0xff))) throw PdfObjError.syntax();
        if (p.keyword("xref")) {
            for (;;) {
                p.skipSpace();
                if (p.keyword("trailer")) break;
                long first = p.uint();
                p.skipSpace();
                long count = p.uint();
                if (first < 0 || count < 0 || first >= MAX_OBJECT_NUMBER || count > MAX_OBJECT_NUMBER) {
                    throw PdfObjError.syntax();
                }
                p.skipGap();
                for (long i = 0; i < count; i++) {
                    if (p.pos + 20 > len) throw PdfObjError.syntax();
                    String row = PdfObjects.latin1(b, p.pos, p.pos + 20);
                    String os = row.substring(0, 10);
                    String gs = row.substring(11, 16);
                    String eol = row.substring(18);
                    if (!DIGITS.matcher(os).matches() || !DIGITS.matcher(gs).matches() || row.charAt(10) != ' '
                        || row.charAt(16) != ' ' || !(eol.equals(" \n") || eol.equals(" \r") || eol.equals("\r\n"))) {
                        throw PdfObjError.syntax();
                    }
                    long o = Long.parseLong(os);
                    long g = Long.parseLong(gs);
                    if (o > len || g > 65535) throw PdfObjError.syntax();
                    XrefEnt e;
                    if (row.charAt(17) == 'n') e = useEnt(o, g);
                    else if (row.charAt(17) == 'f') e = FREE;
                    else throw PdfObjError.syntax();
                    p.pos += 20;
                    set(sec, first + i, e);
                }
            }
            Object t = p.value(0);
            if (!isDict(t)) throw PdfObjError.syntax();
            sec.trailer = PdfObjects.dict(t);
            sec.end = p.pos;
            return sec;
        }
        PdfParser.Indirect o = p.indirect(null);
        if (!(o.val instanceof PStream) || !ifaceEq(dget(((PStream) o.val).dict, "Type"), new PName("XRef"))) {
            throw PdfObjError.syntax();
        }
        PStream st = (PStream) o.val;
        byte[] data = budget.decode(st);
        Object w = dget(st.dict, "W");
        if (!isArr(w) || arr(w).size() != 3) throw PdfObjError.syntax();
        int[] width = new int[3];
        for (int i = 0; i < 3; i++) {
            Object x = arr(w).get(i);
            if (!isInt(x) || (Long) x < 0 || (Long) x > 7) throw PdfObjError.syntax();
            width[i] = (int) (long) (Long) x;
        }
        Object size = dget(st.dict, "Size");
        if (!isInt(size) || (Long) size < 0) throw PdfObjError.syntax();
        List<Object> index = List.of(0L, size);
        if (st.dict.containsKey("Index")) {
            Object ix = dget(st.dict, "Index");
            if (!isArr(ix) || arr(ix).size() % 2 != 0) throw PdfObjError.syntax();
            index = arr(ix);
        }
        int row = width[0] + width[1] + width[2];
        if (row == 0) throw PdfObjError.syntax();
        int[] cur = {0};
        for (int i = 0; i < index.size(); i += 2) {
            Object first = index.get(i);
            Object count = index.get(i + 1);
            if (!isInt(first) || !isInt(count) || (Long) first < 0 || (Long) first >= MAX_OBJECT_NUMBER || (Long) count < 0
                || (Long) count > (data.length - cur[0]) / row) {
                throw PdfObjError.syntax();
            }
            long f0 = (Long) first;
            long cnt = (Long) count;
            for (long j = 0; j < cnt; j++) {
                double kind = 1;
                if (width[0] > 0) kind = field(data, cur, width[0]);
                double f2 = field(data, cur, width[1]);
                double f3 = field(data, cur, width[2]);
                XrefEnt e;
                if (kind == 0) e = FREE;
                else if (kind == 1) e = useEnt((long) f2, (long) f3);
                else if (kind == 2) e = new XrefEnt(ENT_COMP, (long) f2, 0, (long) f3);
                else throw PdfObjError.syntax();
                set(sec, f0 + j, e);
            }
        }
        if (cur[0] != data.length) throw PdfObjError.syntax();
        sec.trailer = st.dict;
        sec.end = p.pos;
        return sec;
    }

    /** Big-endian field in double arithmetic, exactly as TS (values above 2^53 round the same way). */
    private static double field(byte[] data, int[] cur, int n) {
        double x = 0;
        for (int i = 0; i < n; i++) x = x * 256 + (data[cur[0] + i] & 0xff);
        cur[0] += n;
        return x;
    }

    private void set(XrefSection sec, long num, XrefEnt e) {
        if (num >= MAX_OBJECT_NUMBER) throw PdfObjError.syntax();
        if (sec.ents.containsKey((int) num)) throw PdfObjError.syntax();
        sec.ents.put((int) num, e);
        budget.node();
    }

    /** Parses in-use object num (header number/generation must match the xref). */
    Object get(int num) {
        if (objs.containsKey(num)) return objs.get(num);
        Object val;
        XrefEnt e = ent(xref, num);
        if (e.kind == ENT_USE) {
            if (e.off >= len) throw PdfObjError.syntax();
            String key = e.off + ",-1";
            CachedObj o = budget.objs.get(key);
            if (o == null || o.end > len) {
                PdfParser p = parser((int) e.off);
                usedLength = false;
                PdfParser.Indirect ind = p.indirect(this::length);
                o = new CachedObj(ind.num, ind.gen, ind.val, p.pos);
                if (!usedLength) budget.objs.put(key, o);
            }
            if (o.num != num || o.gen != e.gen) throw PdfObjError.syntax();
            val = o.val;
        } else if (e.kind == ENT_COMP) {
            ObjStm st = objStm(e.off);
            if (e.idx >= st.nums.size() || st.nums.get((int) e.idx) != num
                || (long) st.first + st.offs.get((int) e.idx) > st.data.length) {
                throw PdfObjError.syntax();
            }
            String key = ent(xref, e.off).off + "," + e.idx;
            CachedObj o = budget.objs.get(key);
            if (o == null) {
                PdfParser p = new PdfParser(st.data, st.data.length, st.first + st.offs.get((int) e.idx), budget);
                o = new CachedObj(0, 0, p.value(0), 0);
                budget.objs.put(key, o);
            }
            val = o.val;
        } else throw PdfObjError.syntax();
        objs.put(num, val);
        return val;
    }

    /** The object r points at; null for an unused number; a generation mismatch is an error. */
    Object deref(PRef r) {
        XrefEnt e = ent(xref, r.num);
        if (!inUse(e)) return null;
        if ((e.kind == ENT_USE && e.gen != r.gen) || (e.kind == ENT_COMP && r.gen != 0)) throw PdfObjError.syntax();
        return get(r.num);
    }

    Object resolve(Object x) {
        return x instanceof PRef ? deref((PRef) x) : x;
    }

    Long length(PRef r) {
        if (inLength) throw PdfObjError.syntax();
        inLength = true;
        try {
            Object o = deref(r);
            if (!isInt(o)) throw PdfObjError.syntax();
            usedLength = true;
            return (Long) o;
        } finally {
            inLength = false;
        }
    }

    ObjStm objStm(long num) {
        if (ent(xref, num).kind != ENT_USE) throw PdfObjError.syntax();
        Object o = get((int) num);
        long off = ent(xref, num).off;
        ObjStm cached = budget.stms.get(off);
        if (cached != null) return cached;
        if (!(o instanceof PStream)) throw PdfObjError.syntax();
        PStream s = (PStream) o;
        Object n = dget(s.dict, "N");
        Object first = dget(s.dict, "First");
        if (!isInt(n) || !isInt(first) || !isInt(dget(s.dict, "Length"))
            || !ifaceEq(dget(s.dict, "Type"), new PName("ObjStm")) || dget(s.dict, "Extends") != null) {
            throw PdfObjError.syntax();
        }
        byte[] data = budget.decode(s);
        long nn = (Long) n;
        long ff = (Long) first;
        if (nn < 0 || nn > data.length || ff < 0 || ff > data.length) throw PdfObjError.syntax();
        ObjStm st = new ObjStm(data, (int) ff);
        PdfParser p = new PdfParser(data, st.first, 0, budget);
        for (long i = 0; i < nn; i++) {
            p.skipSpace();
            long id = p.uint();
            p.skipSpace();
            long so = p.uint();
            if (id < 0 || so < 0 || id >= MAX_OBJECT_NUMBER || so > data.length) throw PdfObjError.syntax();
            budget.node();
            st.nums.add((int) id);
            st.offs.add((int) so);
        }
        budget.stms.put(off, st);
        return st;
    }

    /** Parses EVERY in-use object and returns the ref numbers going out of each. */
    Map<Integer, List<Integer>> graph() {
        if (refs != null) return refs;
        Map<Integer, List<Integer>> out = new LinkedHashMap<>();
        for (Map.Entry<Integer, XrefEnt> e : xref.entrySet()) {
            if (!inUse(e.getValue())) continue;
            Object o = get(e.getKey());
            List<Integer> to = new ArrayList<>();
            PdfObjects.pdfRefs(o, r -> to.add(r.num));
            out.put(e.getKey(), to);
        }
        refs = out;
        return out;
    }

    /** Merges the xref by following /Prev from the last startxref of b[0, len). */
    static PdfView open(byte[] b, int len, PdfBudget budget) {
        PdfView v = new PdfView(b, len, budget);
        int tail = Math.max(0, len - 1024);
        int i = lastIndex(b, len, tail, "startxref");
        if (i < 0) throw PdfObjError.syntax();
        PdfParser p = v.parser(i);
        long off = p.startxref();
        if (off < 0 || !allGapSpace(b, p.pos, len)) throw PdfObjError.syntax();
        Set<Long> seen = new HashSet<>();
        for (;;) {
            if (v.sections.size() == MAX_XREF_SECTIONS || seen.contains(off) || off >= len) throw PdfObjError.syntax();
            seen.add(off);
            XrefSection sec = v.section((int) off);
            v.sections.add(sec);
            if (dget(sec.trailer, "Encrypt") != null || dget(sec.trailer, "XRefStm") != null) throw PdfObjError.syntax();
            if (!sec.trailer.containsKey("Prev")) break;
            Object prev = dget(sec.trailer, "Prev");
            if (!isInt(prev) || (Long) prev < 0 || (Long) prev >= len) throw PdfObjError.syntax();
            off = (Long) prev;
        }
        for (XrefSection sec : v.sections) {
            for (Map.Entry<Integer, XrefEnt> e : sec.ents.entrySet()) v.xref.putIfAbsent(e.getKey(), e.getValue());
        }
        v.trailer = v.sections.get(0).trailer;
        Object size = dget(v.trailer, "Size");
        if (!isInt(size)) throw PdfObjError.syntax();
        for (Map.Entry<Integer, XrefEnt> e : v.xref.entrySet()) {
            if (inUse(e.getValue()) && (e.getKey() >= (Long) size || e.getKey() == 0)) throw PdfObjError.syntax();
        }
        return v;
    }

    private static int lastIndex(byte[] b, int len, int from, String s) {
        outer:
        for (int i = len - s.length(); i >= from; i--) {
            for (int j = 0; j < s.length(); j++) if ((b[i + j] & 0xff) != s.charAt(j)) continue outer;
            return i;
        }
        return -1;
    }
}
