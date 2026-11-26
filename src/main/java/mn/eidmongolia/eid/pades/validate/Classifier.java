package mn.eidmongolia.eid.pades.validate;

import static mn.eidmongolia.eid.pades.validate.PdfObjects.ENT_COMP;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ENT_USE;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.allGapSpace;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.arr;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.dget;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.dict;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ent;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.entEq;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.ifaceEq;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.inUse;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isArr;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isDict;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isInt;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isName;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isRef;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.isStr;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.pdfEqual;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.pdfRefs;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import mn.eidmongolia.eid.pades.validate.PdfObjects.ObjStm;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PName;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PReal;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PRef;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStr;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStream;
import mn.eidmongolia.eid.pades.validate.PdfObjects.XrefEnt;
import mn.eidmongolia.eid.pades.validate.PdfObjects.XrefSection;

/** One base → fin step of the revision analysis (TS revisions.ts Classifier). Every rejection is a PdfObjError. */
final class Classifier {
    private static final List<String> SIG_FIELD_KEYS =
        List.of("Type", "Subtype", "FT", "T", "TU", "V", "Rect", "P", "F", "Ff", "M", "AP");
    private static final List<String> SIG_DICT_KEYS = List.of("Type", "Filter", "SubFilter", "Contents", "ByteRange", "Cert",
        "M", "Name", "Location", "Reason", "ContactInfo", "Reference", "Prop_Build", "Prop_AuthTime", "Prop_AuthType",
        "Changes", "R", "V", "TransformMethod", "TransformParams");
    private static final List<String> OWN_FIELD_KEYS = List.of("Type", "Subtype", "Rect", "P", "F", "FT", "T", "V");
    private static final List<String> OWN_SIG_DICT_KEYS = List.of("Type", "Filter", "SubFilter", "Prop_Build", "ByteRange",
        "Contents", "TransformMethod", "TransformParams", "Name", "Location", "Reason", "ContactInfo", "M");
    private static final List<String> PADES_SIG_DICT_KEYS =
        List.of("Type", "Filter", "SubFilter", "ByteRange", "Contents", "M", "Name", "Reason");
    private static final List<String> LTV_ROLES =
        List.of("catalog", "dss", "vri", "vrient", "ltvarr", "ltv", "info", "metadata");

    final PdfView base;
    final PdfView fin;
    final boolean strict;
    final Map<Integer, long[]> known;
    final PadesSupport support;
    final int end;
    boolean own;
    boolean dssOnly;
    boolean ltvWork;
    boolean infoWork;
    boolean ownProfile;
    final Set<Integer> rewritten = new LinkedHashSet<>();
    final Set<Integer> ownRewrite = new LinkedHashSet<>();
    int root;
    final Set<Integer> changed = new LinkedHashSet<>();
    final Set<Integer> isNew = new LinkedHashSet<>();
    final Set<Integer> allowed = new LinkedHashSet<>();
    final Set<Integer> exclusive = new LinkedHashSet<>();
    final Set<Integer> infra = new LinkedHashSet<>();
    final Set<Integer> xrefSelf = new LinkedHashSet<>();
    final Map<Long, Integer> edges = new HashMap<>();
    final Set<Integer> sigDicts = new LinkedHashSet<>();
    final Set<Integer> widgets = new LinkedHashSet<>();
    final Map<Integer, String> role = new HashMap<>();
    final Set<Integer> seen = new LinkedHashSet<>();
    final Set<Integer> pages = new LinkedHashSet<>();
    final Map<Integer, Integer> widgetP = new LinkedHashMap<>();
    final Map<Integer, Integer> widgetPage = new LinkedHashMap<>();
    final Map<Integer, Integer> annotsOf = new HashMap<>();
    final Set<String> fieldNames = new LinkedHashSet<>();
    boolean visible;
    final Set<Integer> ownVis = new LinkedHashSet<>();
    Map<Integer, SigMeta> sigs = new LinkedHashMap<>();
    String docID = "";
    boolean sigWork;

    Classifier(PdfView base, PdfView fin, boolean strict, Map<Integer, long[]> known, PadesSupport support) {
        this.base = base;
        this.fin = fin;
        this.strict = strict;
        this.known = known;
        this.support = support;
        this.end = base.len;
    }

    private static PdfObjError fail() {
        return PdfObjError.notSignatureOnly();
    }

    private static long ek(int a, int b) {
        return ((long) a << 32) | (b & 0xffffffffL);
    }

    void edge(int a, int b) {
        edges.merge(ek(a, b), 1, Integer::sum);
    }

    void claim(int num, String r) {
        String cur = role.get(num);
        if (cur != null && !cur.equals(r)) throw fail();
        role.put(num, r);
    }

    private static boolean sameExcept(Map<String, Object> a, Map<String, Object> b, String... keys) {
        List<String> ks = Arrays.asList(keys);
        for (Map<String, Object> d : Arrays.asList(a, b)) {
            if (d == null) continue;
            for (String k : d.keySet()) {
                if (!ks.contains(k) && !pdfEqual(dget(a, k), dget(b, k))) return false;
            }
        }
        return true;
    }

    static boolean onlyKeys(Map<String, Object> d, List<String> keys) {
        if (d == null) return true;
        for (String k : d.keySet()) if (!keys.contains(k)) return false;
        return true;
    }

    static boolean onlyKeys(Map<String, Object> d, String... keys) {
        return onlyKeys(d, Arrays.asList(keys));
    }

    private static List<String> sortedKeys(Map<String, Object> d) {
        if (d == null) return Collections.emptyList();
        List<String> out = new ArrayList<>(d.keySet());
        Collections.sort(out);
        return out;
    }

    /** "M.m" (1.0 … 2.9) → M*10+m; -1 when not a version. */
    private static int pdfVersion(String s) {
        if (s.length() != 3 || s.charAt(1) != '.' || (s.charAt(0) != '1' && s.charAt(0) != '2') || s.charAt(2) < '0'
            || s.charAt(2) > '9') {
            return -1;
        }
        return (s.charAt(0) - '0') * 10 + (s.charAt(2) - '0');
    }

    private static boolean trailerCompatible(Map<String, Object> base, Map<String, Object> later, boolean infoOmitted) {
        if (!infoOmitted && !pdfEqual(dget(later, "Info"), dget(base, "Info"))) return false;
        Object bid = dget(base, "ID");
        if (isArr(bid) && arr(bid).size() == 2 && later.containsKey("ID")) {
            Object a = dget(later, "ID");
            if (!isArr(a) || arr(a).size() != 2 || !pdfEqual(arr(a).get(0), arr(bid).get(0))) return false;
        }
        Object bsv = dget(base, "Size");
        long bs = isInt(bsv) ? (Long) bsv : 0;
        Object ls = dget(later, "Size");
        return isInt(ls) && (Long) ls >= bs;
    }

    void run() {
        structure();
        diff();
        Map<Integer, List<Integer>> refs = fin.graph();
        Set<Integer> reach = new LinkedHashSet<>();
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        pdfRefs(fin.trailer, r -> queue.push(r.num));
        while (!queue.isEmpty()) {
            int n = queue.pop();
            if (reach.contains(n) || !inUse(ent(fin.xref, n))) continue;
            reach.add(n);
            for (int t : refs.getOrDefault(n, Collections.emptyList())) queue.push(t);
        }
        for (int n : isNew) if (strict || reach.contains(n)) exclusive.add(n);
        boolean[] dangling = {false};
        pdfRefs(base.trailer, r -> dangling[0] = dangling[0] || isNew.contains(r.num));
        for (Map.Entry<Integer, XrefEnt> me : fin.xref.entrySet()) {
            int num = me.getKey();
            if (!inUse(me.getValue()) || isNew.contains(num)) continue;
            if (changed.contains(num)) {
                pdfRefs(base.get(num), r -> dangling[0] = dangling[0] || isNew.contains(r.num));
            } else {
                for (int to : refs.getOrDefault(num, Collections.emptyList())) dangling[0] = dangling[0] || isNew.contains(to);
            }
        }
        if (dangling[0]) throw fail();
        catalog();
        List<Integer> ps = new ArrayList<>(pages);
        Collections.sort(ps);
        for (int p : ps) page(p);
        for (int n : ownRewrite) {
            String r = role.get(n);
            if (!changed.contains(n) || !allowed.contains(n) || !("page".equals(r) || "annots".equals(r))) throw fail();
        }
        for (Map.Entry<Integer, Integer> me : widgetP.entrySet()) {
            int w = me.getKey();
            int p = me.getValue();
            boolean placed = widgetPage.containsKey(w);
            int at = widgetPage.getOrDefault(w, 0);
            if ((p != 0 && (!pages.contains(p) || (placed && at != p))) || (ownVis.contains(w) && (!placed || at != p))) {
                throw fail();
            }
        }
        if (dssOnly) info();
        for (int n : changed) {
            if (!allowed.contains(n) && !infra.contains(n) && (strict || reach.contains(n))) throw fail();
            String r = role.get(n);
            if (own && !isNew.contains(n) && !(allowed.contains(n) && ("page".equals(r) || "annots".equals(r)))) throw fail();
        }
        if (dssOnly) dssOnlyRules();
        if (own) {
            if (!isNew.contains(root) || sigDicts.size() != widgets.size() || sigDicts.isEmpty()
                || (strict && sigDicts.size() != 1) || (visible && ownVis.isEmpty())) {
                throw fail();
            }
            for (int n : isNew) {
                String r = role.getOrDefault(n, "");
                if (strict && !xrefSelf.contains(n) && !r.equals("sig") && !r.equals("field") && !r.equals("catalog")
                    && (!r.equals("ap") || ownVis.isEmpty())) {
                    throw fail();
                }
            }
        }
        for (Map.Entry<Integer, List<Integer>> me : refs.entrySet()) {
            int from = me.getKey();
            if ((!strict && !reach.contains(from)) || infra.contains(from)) continue;
            Map<Integer, Integer> count = new LinkedHashMap<>();
            for (int to : me.getValue()) if (exclusive.contains(to)) count.merge(to, 1, Integer::sum);
            for (Map.Entry<Integer, Integer> c : count.entrySet()) {
                if (edges.getOrDefault(ek(from, c.getKey()), 0).intValue() != c.getValue()) throw fail();
            }
        }
        boolean[] bad = {false};
        for (Map.Entry<String, Object> me : fin.trailer.entrySet()) {
            if (!me.getKey().equals("Root")) pdfRefs(me.getValue(), r -> bad[0] = bad[0] || exclusive.contains(r.num));
        }
        if (bad[0] || (sigDicts.isEmpty() && sigWork)) throw fail();
    }

    /** The xref chain, trailers, and full coverage of the bytes after the signed range. */
    void structure() {
        List<XrefSection> fs = fin.sections;
        List<XrefSection> bs = base.sections;
        int k = fs.size() - bs.size();
        if (k < 1 || (strict && k != 1)) throw fail();
        for (int i = 0; i < bs.size(); i++) if (fs.get(k + i).off != bs.get(i).off) throw fail();
        PdfParser lin = fin.parser(0);
        lin.skip();
        boolean linearized = false;
        try {
            PdfParser.Indirect o = lin.indirect(null);
            linearized = isDict(o.val) && dget(dict(o.val), "Linearized") != null
                && ifaceEq(dget(dict(o.val), "L"), (long) fin.len);
        } catch (RuntimeException e) {
            // Go: skipped when it does not parse
        }
        if (linearized) throw fail();
        List<int[]> spans = new ArrayList<>();
        for (XrefSection s : fs.subList(0, k)) {
            boolean infoOmitted = own && isName(dget(s.trailer, "Type"), "XRef") && dget(s.trailer, "Info") == null;
            if (s.off < end || !trailerCompatible(base.trailer, s.trailer, infoOmitted)) throw fail();
            PdfParser p = fin.parser(s.end);
            long at = p.startxref();
            if (at < 0 || at != s.off) throw fail();
            spans.add(new int[] {s.start, p.pos});
            List<String> keys = new ArrayList<>(List.of("Size", "Root", "Info", "ID", "Prev"));
            if ((fin.b[s.start] & 0xff) == 'x') {
                for (int i = s.start; i < s.end; i++) {
                    int c = fin.b[i] & 0xff;
                    if (c == 0 || c == '%') throw fail();
                }
            } else {
                keys.addAll(List.of("Type", "W", "Index", "Length", "Filter", "DecodeParms"));
                PdfParser sp = fin.parser(s.start);
                sp.strict = true;
                sp.indirect(null);
            }
            if (!onlyKeys(s.trailer, keys)) throw fail();
            Map<Long, Integer> packed = new LinkedHashMap<>();
            for (Map.Entry<Integer, XrefEnt> me : s.ents.entrySet()) {
                int num = me.getKey();
                XrefEnt e = me.getValue();
                if (own && e.kind != ENT_USE) throw fail();
                if (own && inUse(ent(base.xref, num))) ownRewrite.add(num);
                if (dssOnly && ownProfile && inUse(e) && inUse(ent(base.xref, num))) rewritten.add(num);
                if (e.kind == ENT_USE) {
                    if (e.off < end || e.off >= fin.len) throw fail();
                    int c = fin.b[(int) e.off] & 0xff;
                    if (c < '0' || c > '9') throw fail();
                    if (e.off == s.start) {
                        infra.add(num);
                        xrefSelf.add(num);
                        continue;
                    }
                    PdfParser p2 = fin.parser((int) e.off);
                    p2.strict = true;
                    PdfParser.Indirect o = p2.indirect(fin::length);
                    if (o.num != num || o.gen != e.gen) throw fail();
                    spans.add(new int[] {(int) e.off, p2.pos});
                } else if (e.kind == ENT_COMP) {
                    XrefEnt st = ent(fin.xref, e.off);
                    if (st.kind != ENT_USE || st.off < end) throw fail();
                    if (own) throw fail();
                    packed.merge(e.off, 1, Integer::sum);
                }
            }
            for (Map.Entry<Long, Integer> me : packed.entrySet()) {
                if (!strict) continue;
                long stm = me.getKey();
                ObjStm st = fin.objStm(stm);
                if (!s.ents.containsKey((int) stm) || st.nums.size() != me.getValue()) throw fail();
                for (int off : st.offs) {
                    PdfParser sp = new PdfParser(st.data, st.data.length, (int) Math.min((long) st.first + off, st.data.length),
                        fin.budget, true);
                    sp.value(0);
                }
                infra.add((int) stm);
            }
        }
        spans.sort((x, y) -> Integer.compare(x[0], y[0]));
        int cur = end;
        for (int[] sp : spans) {
            if (sp[0] < cur || !allGapSpace(fin.b, cur, sp[0])) throw fail();
            cur = sp[1];
        }
        if (!allGapSpace(fin.b, cur, fin.len)) throw fail();
    }

    /** Compares the base and final xref; fills changed / isNew. */
    void diff() {
        for (Map.Entry<Integer, XrefEnt> me : base.xref.entrySet()) {
            XrefEnt be = me.getValue();
            if (!inUse(be)) continue;
            if (be.kind == ENT_USE && be.off >= end) throw fail();
            if (!inUse(ent(fin.xref, me.getKey()))) throw fail();
        }
        for (Map.Entry<Integer, XrefEnt> me : fin.xref.entrySet()) {
            int num = me.getKey();
            XrefEnt fe = me.getValue();
            if (!inUse(fe)) continue;
            XrefEnt be = ent(base.xref, num);
            if (!inUse(be)) {
                isNew.add(num);
                changed.add(num);
                continue;
            }
            if (entEq(be, fe) && (be.kind == ENT_USE || entEq(ent(base.xref, be.off), ent(fin.xref, fe.off)))) continue;
            Object bo = base.get(num);
            Object fo = fin.get(num);
            boolean unpack = be.kind == ENT_COMP && fe.kind == ENT_USE && fe.gen == 0
                && (own || (!strict && ownProfile && !dssOnly));
            if ((be.kind != fe.kind || be.gen != fe.gen) && !unpack) throw fail();
            if (unpack && pdfEqual(bo, fo)) throw fail();
            if (!pdfEqual(bo, fo)) changed.add(num);
        }
    }

    /** Result of container(): the final value and the object number owning it. */
    static final class Node {
        final Object val;
        final int num;

        Node(Object val, int num) {
            this.val = val;
            this.num = num;
        }
    }

    /** Resolves final value fv; a ref must point at a new object or at exactly the base's one. */
    Node container(Object bv, Object fv, int owner, String r) {
        if (!(fv instanceof PRef)) return new Node(fv, owner);
        PRef ref = (PRef) fv;
        if (!isNew.contains(ref.num) && !ifaceEq(bv, fv)) throw fail();
        claim(ref.num, r);
        Object val = fin.deref(ref);
        edge(owner, ref.num);
        if (changed.contains(ref.num)) allowed.add(ref.num);
        return new Node(val, ref.num);
    }

    Map<String, Object> baseDict(Object v) {
        Object o = base.resolve(v);
        if (o == null) return null;
        if (!isDict(o)) throw fail();
        return dict(o);
    }

    List<Object> baseArr(Object v) {
        Object o = base.resolve(v);
        if (o == null) return null;
        if (!isArr(o)) throw fail();
        return arr(o);
    }

    private static List<Object> orEmpty(List<Object> a) {
        return a == null ? Collections.emptyList() : a;
    }

    void catalog() {
        Object fr = dget(fin.trailer, "Root");
        Object br = dget(base.trailer, "Root");
        if (!isRef(fr) || !isRef(br) || (((PRef) fr).num != ((PRef) br).num && !isNew.contains(((PRef) fr).num))) throw fail();
        Object fco = fin.deref((PRef) fr);
        Object bco = base.deref((PRef) br);
        List<String> except = new ArrayList<>(List.of("AcroForm", "DSS", "Perms", "Version"));
        if (dssOnly) except.addAll(List.of("Extensions", "Metadata"));
        if (!isDict(fco) || !isDict(bco) || !sameExcept(dict(bco), dict(fco), except.toArray(new String[0]))) throw fail();
        Map<String, Object> fc = dict(fco);
        Map<String, Object> bc = dict(bco);
        if (own) {
            if (!sameExcept(bc, fc, "AcroForm", "Version") || (!pdfEqual(dget(bc, "Version"), dget(fc, "Version"))
                && (dget(bc, "Version") != null || !ifaceEq(dget(fc, "Version"), new PName("1.5"))))) {
                throw fail();
            }
        }
        root = ((PRef) fr).num;
        allowed.add(root);
        claim(root, "catalog");
        pageTree(dget(fc, "Pages"));
        if (!pdfEqual(dget(bc, "Version"), dget(fc, "Version"))) {
            Object fvn = dget(fc, "Version");
            int nv = pdfVersion(fvn instanceof PName ? ((PName) fvn).v : "");
            PdfView bb = base;
            String head = PdfObjects.latin1(bb.b, Math.min(bb.len, 5), Math.min(bb.len, 8));
            int floor = pdfVersion(head);
            boolean ok2 = floor >= 0;
            if (bc.containsKey("Version")) {
                Object bn = dget(bc, "Version");
                int bv = pdfVersion(bn instanceof PName ? ((PName) bn).v : "");
                ok2 = ok2 && bv >= 0;
                floor = Math.max(Math.max(floor, 0), Math.max(bv, 0));
            }
            String pfx = PdfObjects.latin1(bb.b, 0, Math.min(5, bb.len));
            if (nv < 0 || !ok2 || !pfx.equals("%PDF-") || nv < Math.max(floor, 0)) throw fail();
            if (dssOnly) infoWork = true;
            else sigWork = true;
        }
        if (dssOnly) {
            extensions(dget(bc, "Extensions"), dget(fc, "Extensions"));
            metadata(dget(bc, "Metadata"), dget(fc, "Metadata"));
        }
        acroForm(dget(bc, "AcroForm"), dget(fc, "AcroForm"));
        if (!pdfEqual(dget(bc, "Perms"), dget(fc, "Perms"))) {
            sigWork = true;
            Map<String, Object> bpd = baseDict(dget(bc, "Perms"));
            Node pn = container(dget(bc, "Perms"), dget(fc, "Perms"), root, "perms");
            if (!isDict(pn.val) || !onlyKeys(dict(pn.val), "DocMDP", "UR", "UR3")) throw fail();
            Map<String, Object> pv = dict(pn.val);
            for (String key : sortedKeys(pv)) {
                Object r = dget(pv, key);
                if (!isRef(r) || (!sigDicts.contains(((PRef) r).num)
                    && (changed.contains(((PRef) r).num) || !ifaceEq(dget(bpd, key), r)))) {
                    throw fail();
                }
                edge(pn.num, ((PRef) r).num);
            }
        }
        dss(dget(bc, "DSS"), dget(fc, "DSS"));
    }

    void pageTree(Object rootRef) {
        ArrayDeque<Object> stack = new ArrayDeque<>();
        stack.push(rootRef == null ? NULL : rootRef);
        Set<Integer> visited = new LinkedHashSet<>();
        while (!stack.isEmpty()) {
            Object r = stack.pop();
            if (!(r instanceof PRef) || visited.contains(((PRef) r).num)) throw fail();
            int num = ((PRef) r).num;
            visited.add(num);
            Object o = fin.deref((PRef) r);
            Map<String, Object> d = isDict(o) ? dict(o) : null;
            Object t = dget(d, "Type");
            if (ifaceEq(t, new PName("Page"))) pages.add(num);
            else if (ifaceEq(t, new PName("Pages"))) {
                Object kids = fin.resolve(dget(d, "Kids"));
                if (!isArr(kids)) throw fail();
                for (Object kid : arr(kids)) stack.push(kid == null ? NULL : kid);
            } else throw fail();
        }
    }

    /** ArrayDeque rejects null; a placeholder that is never a PRef. */
    private static final Object NULL = new Object();

    void page(int p) {
        Object fo = fin.get(p);
        if (!isDict(fo) || isNew.contains(p)) throw fail();
        Map<String, Object> fd = dict(fo);
        Map<String, Object> bd = fd;
        if (changed.contains(p)) {
            Object bo = base.get(p);
            if (!isDict(bo) || !sameExcept(dict(bo), fd, "Annots")) throw fail();
            bd = dict(bo);
            claim(p, "page");
            sigWork = true;
            allowed.add(p);
        }
        Object ar = dget(fd, "Annots");
        if (!changed.contains(p) && !(ar instanceof PRef && changed.contains(((PRef) ar).num))) return;
        if (ar == null) {
            if (dget(bd, "Annots") != null) throw fail();
            return;
        }
        List<Object> ba = orEmpty(baseArr(dget(bd, "Annots")));
        Node an = container(dget(bd, "Annots"), ar, p, "annots");
        if (!isArr(an.val)) throw fail();
        List<Object> fa = arr(an.val);
        int anum = an.num;
        if (anum != p) {
            if (annotsOf.containsKey(anum)) throw fail();
            annotsOf.put(anum, p);
            if (changed.contains(anum)) {
                sigWork = true;
                exclusive.add(anum);
            }
        }
        if (fa.size() < ba.size()) throw fail();
        for (int i = 0; i < fa.size(); i++) {
            Object e = fa.get(i);
            if (i < ba.size()) {
                if (!pdfEqual(ba.get(i), e)) throw fail();
                continue;
            }
            int num = e instanceof PRef ? ((PRef) e).num : 0;
            if (!(e instanceof PRef) || !widgets.contains(num) || widgetPage.containsKey(num)) throw fail();
            widgetPage.put(num, p);
            edge(anum, num);
        }
    }

    void acroForm(Object bv, Object fv) {
        if (fv == null) {
            if (bv != null) throw fail();
            return;
        }
        Map<String, Object> bd = baseDict(bv);
        Node an = container(bv, fv, root, "acroform");
        if (!isDict(an.val) || !sameExcept(bd, dict(an.val), "Fields", "SigFlags")) throw fail();
        Map<String, Object> fd = dict(an.val);
        int num = an.num;
        if (!pdfEqual(dget(bd, "SigFlags"), dget(fd, "SigFlags"))) {
            Object nf = dget(fd, "SigFlags");
            Object ofv = dget(bd, "SigFlags");
            boolean was = isInt(ofv);
            long of = was ? (Long) ofv : 0;
            if (!isInt(nf) || ((Long) nf != 1 && (Long) nf != 3) || (ofv != null && !was) || (Long) nf < of) throw fail();
        }
        if (!pdfEqual(dget(bd, "SigFlags"), dget(fd, "SigFlags")) || bd == null) sigWork = true;
        if (own) {
            if (!isDict(fv) || !isArr(dget(fd, "Fields")) || !ifaceEq(dget(fd, "SigFlags"), 3L)) throw fail();
        }
        List<Object> bf = orEmpty(baseArr(dget(bd, "Fields")));
        if (own) {
            for (Object e : bf) {
                Object o = base.resolve(e);
                if (!isDict(o) || !(e instanceof PRef)) throw fail();
                Object t = dget(dict(o), "T");
                if (t instanceof PStr) fieldNames.add(Revisions.pdfTextString((PStr) t));
            }
        }
        Node fn = container(dget(bd, "Fields"), dget(fd, "Fields"), num, "fields");
        if ((fn.val != null && !isArr(fn.val)) || (isArr(fn.val) ? arr(fn.val).size() : 0) < bf.size()) throw fail();
        List<Object> ff = isArr(fn.val) ? arr(fn.val) : Collections.emptyList();
        for (int i = 0; i < ff.size(); i++) {
            Object e = ff.get(i);
            if (i < bf.size()) {
                if (!pdfEqual(bf.get(i), e)) throw fail();
                if (e instanceof PRef && changed.contains(((PRef) e).num)) {
                    if (own) throw fail();
                    filledField(((PRef) e).num);
                }
            } else if (!(e instanceof PRef)) throw fail();
            else newField((PRef) e, fn.num);
        }
    }

    void newField(PRef r, int owner) {
        if (!isNew.contains(r.num) || widgets.contains(r.num)) throw fail();
        Object dv = fin.deref(r);
        if (!isDict(dv) || !onlyKeys(dict(dv), SIG_FIELD_KEYS) || !ifaceEq(dget(dict(dv), "FT"), new PName("Sig"))) throw fail();
        Map<String, Object> d = dict(dv);
        if (d.containsKey("Type") && !ifaceEq(dget(d, "Type"), new PName("Annot"))) throw fail();
        if (d.containsKey("Subtype") && !ifaceEq(dget(d, "Subtype"), new PName("Widget"))) throw fail();
        for (String k : List.of("T", "TU", "M")) if (d.containsKey(k) && !isStr(dget(d, k))) throw fail();
        for (String k : List.of("F", "Ff")) if (d.containsKey(k) && !isInt(dget(d, k))) throw fail();
        if (own) {
            if (d.containsKey("AP")) {
                OwnAppearance.ownVisible(this, d, r.num);
                ownVis.add(r.num);
            } else if (!onlyKeys(d, OWN_FIELD_KEYS) || !ifaceEq(dget(d, "Type"), new PName("Annot"))
                || !ifaceEq(dget(d, "Subtype"), new PName("Widget"))
                || !pdfEqual(dget(d, "Rect"), List.of(0L, 0L, 0L, 0L)) || !ifaceEq(dget(d, "F"), 132L)) {
                throw fail();
            }
            String name = Revisions.ownText(dget(d, "T"), 32);
            if (name == null || !ownFieldName(name) || !ifaceEq(dget(d, "T"), new PStr(name)) || fieldNames.contains(name)) {
                throw fail();
            }
            fieldNames.add(name);
        }
        widgetP.put(r.num, 0);
        if (d.containsKey("P")) {
            Object pr = dget(d, "P");
            if (!(pr instanceof PRef)) throw fail();
            widgetP.put(r.num, ((PRef) pr).num);
        }
        claim(r.num, "field");
        sigWork = true;
        widgets.add(r.num);
        allowed.add(r.num);
        edge(owner, r.num);
        sigValue(dget(d, "V"), r.num);
        appearance(null, d, r.num);
    }

    /** "Signature N", N = 1…9999 without a leading zero. */
    private static boolean ownFieldName(String s) {
        if (!s.startsWith("Signature ")) return false;
        String n = s.substring("Signature ".length());
        if (n.length() < 1 || n.length() > 4 || n.charAt(0) == '0') return false;
        for (int i = 0; i < n.length(); i++) if (n.charAt(i) < '0' || n.charAt(i) > '9') return false;
        return true;
    }

    void filledField(int num) {
        Object bo = base.get(num);
        Object fo = fin.get(num);
        if (!isDict(bo) || !isDict(fo)) throw fail();
        Map<String, Object> bd = dict(bo);
        Map<String, Object> fd = dict(fo);
        if (!ifaceEq(dget(bd, "FT"), new PName("Sig")) || dget(bd, "V") != null || dget(bd, "Kids") != null
            || !sameExcept(bd, fd, "V", "AP", "M")) {
            throw fail();
        }
        if (bd.containsKey("Type") && !ifaceEq(dget(bd, "Type"), new PName("Annot"))) throw fail();
        if (bd.containsKey("Subtype") && !ifaceEq(dget(bd, "Subtype"), new PName("Widget"))) throw fail();
        if (fd.containsKey("M") && !isStr(dget(fd, "M"))) throw fail();
        claim(num, "field");
        sigWork = true;
        allowed.add(num);
        sigValue(dget(fd, "V"), num);
        appearance(bd, fd, num);
    }

    void sigValue(Object v, int owner) {
        if (!(v instanceof PRef) || !isNew.contains(((PRef) v).num) || sigDicts.contains(((PRef) v).num)) throw fail();
        PRef r = (PRef) v;
        claim(r.num, "sig");
        Object dv = fin.deref(r);
        if (!isDict(dv) || !onlyKeys(dict(dv), SIG_DICT_KEYS)) throw fail();
        Map<String, Object> d = dict(dv);
        if (own && (!onlyKeys(d, OWN_SIG_DICT_KEYS) || !ifaceEq(dget(d, "Type"), new PName("Sig")))) throw fail();
        if (own) {
            if (ifaceEq(dget(d, "SubFilter"), new PName("ETSI.CAdES.detached")) && (!onlyKeys(d, PADES_SIG_DICT_KEYS)
                || !ifaceEq(dget(d, "Filter"), new PName("Adobe.PPKLite")) || dget(d, "M") == null)) {
                throw fail();
            }
            for (String k : List.of("Name", "Location", "Reason", "ContactInfo", "M")) {
                if (!d.containsKey(k)) continue;
                String text = Revisions.ownText(dget(d, k), Revisions.OWN_TEXT_LIMIT);
                if (text == null || (k.equals("M") && !Revisions.ownDate(text))) throw fail();
            }
        }
        if (d.containsKey("Type") && !ifaceEq(dget(d, "Type"), new PName("Sig"))) throw fail();
        Object br = dget(d, "ByteRange");
        if (!isArr(br) || !isStr(dget(d, "Contents")) || arr(br).size() != 4) throw fail();
        long[] n = new long[4];
        for (int i = 0; i < 4; i++) {
            Object x = arr(br).get(i);
            if (!isInt(x)) throw fail();
            n[i] = (Long) x;
        }
        // n[2] + n[3] is exact in TS (bigint); an int64 overflow is far past end.
        boolean coversEnd;
        try {
            coversEnd = Math.addExact(n[2], n[3]) > end;
        } catch (ArithmeticException e) {
            coversEnd = n[2] > 0;
        }
        if (n[0] != 0 || n[1] <= 0 || n[2] <= n[1] || n[3] < 0 || !coversEnd) throw fail();
        long[] kb = known.get(r.num);
        if (kb == null || kb.length != 4 || !Arrays.equals(kb, n)) throw fail();
        boolean bad = false;
        boolean[] hit = {false};
        for (Map.Entry<String, Object> me : d.entrySet()) {
            String k = me.getKey();
            Object val = me.getValue();
            if (!k.equals("Reference")) {
                pdfRefs(val, x -> hit[0] = true);
                continue;
            }
            bad = bad || !isArr(val);
            for (Object row : isArr(val) ? arr(val) : Collections.emptyList()) {
                if (!isDict(row) || !onlyKeys(dict(row), "Type", "TransformMethod", "TransformParams", "DigestMethod", "Data")) {
                    bad = true;
                    continue;
                }
                for (Map.Entry<String, Object> re : dict(row).entrySet()) {
                    Object rv = re.getValue();
                    if (!re.getKey().equals("Data")) pdfRefs(rv, x -> hit[0] = true);
                    else if (rv instanceof PRef && ((PRef) rv).num == root) edge(r.num, root);
                    else if (rv instanceof PRef && ifaceEq(rv, dget(base.trailer, "Root"))) {
                        // the base Catalog
                    } else bad = true;
                }
            }
        }
        if (bad || hit[0]) throw fail();
        sigDicts.add(r.num);
        allowed.add(r.num);
        edge(owner, r.num);
    }

    void appearance(Map<String, Object> baseField, Map<String, Object> d, int widget) {
        if (d.containsKey("Rect")) {
            Object a = dget(d, "Rect");
            if (!isArr(a) || arr(a).size() != 4) throw fail();
            double[] f = new double[4];
            for (int i = 0; i < 4; i++) {
                Object x = arr(a).get(i);
                if (isInt(x)) f[i] = (double) (long) (Long) x;
                else if (x instanceof PReal) f[i] = ((PReal) x).v;
                else throw fail();
            }
            if (f[0] != f[2] && f[1] != f[3]) visible = true;
        }
        if (!d.containsKey("AP")) return;
        Object ap = dget(d, "AP");
        visible = true;
        if (pdfEqual(dget(baseField, "AP"), ap)) return;
        if (!isDict(ap) || !onlyKeys(dict(ap), "N", "R", "D")) throw fail();
        ArrayDeque<Integer> queue = new ArrayDeque<>();
        for (String key : sortedKeys(dict(ap))) {
            Object r = dget(dict(ap), key);
            if (!(r instanceof PRef) || !isNew.contains(((PRef) r).num)) throw fail();
            if (!(fin.deref((PRef) r) instanceof PStream)) throw fail();
            edge(widget, ((PRef) r).num);
            queue.push(((PRef) r).num);
        }
        while (!queue.isEmpty()) {
            int n = queue.pop();
            if (!changed.contains(n)) continue;
            if (!isNew.contains(n) || infra.contains(n)) throw fail();
            claim(n, "ap");
            if (seen.contains(n)) continue;
            seen.add(n);
            allowed.add(n);
            pdfRefs(fin.get(n), t -> {
                edge(n, t.num);
                queue.push(t.num);
            });
        }
    }

    Node dssNode(Object bv, Object fv, int owner, String r) {
        Node nd = container(bv, fv, owner, r);
        if (nd.num != owner && changed.contains(nd.num)) {
            exclusive.add(nd.num);
            ltvWork = true;
        }
        return nd;
    }

    Set<Integer> baseLTVStreams(Map<String, Object> bd) {
        Set<Integer> out = new LinkedHashSet<>();
        addRefs(out, bd, "Certs", "OCSPs", "CRLs");
        Map<String, Object> vri = baseDict(dget(bd, "VRI"));
        if (vri != null) {
            for (Object e : vri.values()) {
                Map<String, Object> ed = baseDict(e);
                addRefs(out, ed, "Cert", "OCSP", "CRL");
                Object ts = dget(ed, "TS");
                if (ts instanceof PRef) out.add(((PRef) ts).num);
            }
        }
        return out;
    }

    private void addRefs(Set<Integer> out, Map<String, Object> d, String... keys) {
        for (String k : keys) {
            for (Object e : orEmpty(baseArr(dget(d, k)))) if (e instanceof PRef) out.add(((PRef) e).num);
        }
    }

    void dss(Object bv, Object fv) {
        if (fv == null) {
            if (bv != null) throw fail();
            return;
        }
        Map<String, Object> bd = baseDict(bv);
        Set<Integer> old = baseLTVStreams(bd);
        Node dn = dssNode(bv, fv, root, "dss");
        if (!isDict(dn.val) || !onlyKeys(dict(dn.val), "Type", "VRI", "Certs", "OCSPs", "CRLs")) throw fail();
        Map<String, Object> fd = dict(dn.val);
        for (String k : List.of("Certs", "OCSPs", "CRLs")) ltvArray(dget(bd, k), dget(fd, k), dn.num, old);
        if (dget(fd, "VRI") == null) return;
        Map<String, Object> bvri = baseDict(dget(bd, "VRI"));
        Node vn = dssNode(dget(bd, "VRI"), dget(fd, "VRI"), dn.num, "vri");
        if (!isDict(vn.val)) throw fail();
        Map<String, Object> fvri = dict(vn.val);
        for (String key : sortedKeys(fvri)) {
            Map<String, Object> bed = baseDict(dget(bvri, key));
            Node en = dssNode(dget(bvri, key), dget(fvri, key), vn.num, "vrient");
            if (!isDict(en.val) || !onlyKeys(dict(en.val), "Type", "Cert", "OCSP", "CRL", "TU", "TS")) throw fail();
            Map<String, Object> fed = dict(en.val);
            for (String k : List.of("Cert", "OCSP", "CRL")) ltvArray(dget(bed, k), dget(fed, k), en.num, old);
            if (dget(fed, "TU") != null && !isStr(dget(fed, "TU"))) throw fail();
            if (fed.containsKey("TS")) ltvStream(dget(fed, "TS"), en.num, old);
        }
    }

    void ltvArray(Object bv, Object fv, int owner, Set<Integer> old) {
        if (fv == null) return;
        Node an = dssNode(bv, fv, owner, "ltvarr");
        if (!isArr(an.val)) throw fail();
        if (an.num != owner) {
            if (seen.contains(an.num)) return;
            seen.add(an.num);
        }
        for (Object e : arr(an.val)) ltvStream(e, an.num, old);
    }

    void ltvStream(Object v, int owner, Set<Integer> old) {
        if (!(v instanceof PRef)) throw fail();
        PRef r = (PRef) v;
        claim(r.num, "ltv");
        edge(owner, r.num);
        if (!isNew.contains(r.num)) {
            if (changed.contains(r.num) || !old.contains(r.num)) throw fail();
            return;
        }
        Object s = fin.deref(r);
        if (!(s instanceof PStream) || !onlyKeys(((PStream) s).dict, "Length", "Filter", "DecodeParms")) throw fail();
        boolean[] bad = {false};
        pdfRefs(((PStream) s).dict, x -> bad[0] = true);
        if (bad[0]) throw fail();
        allowed.add(r.num);
        ltvWork = true;
    }

    void dssOnlyRules() {
        if (!sigDicts.isEmpty() || !widgets.isEmpty() || sigWork || visible || ((infoWork || ownProfile) && !ltvWork)) {
            throw fail();
        }
        for (int n : changed) {
            if (infra.contains(n) || (!strict && !allowed.contains(n))) continue;
            if (!LTV_ROLES.contains(role.getOrDefault(n, ""))) throw fail();
        }
        for (int n : rewritten) {
            if (!changed.contains(n) || !allowed.contains(n) || !LTV_ROLES.contains(role.getOrDefault(n, ""))) throw fail();
        }
    }

    void extensions(Object bv, Object fv) {
        if (pdfEqual(bv, fv)) return;
        if (!isDict(fv)) throw fail();
        for (Map.Entry<String, Object> me : dict(fv).entrySet()) {
            Object v = me.getValue();
            if (me.getKey().equals("Type")) {
                if (!ifaceEq(v, new PName("Extensions"))) throw fail();
                continue;
            }
            if (isArr(v)) {
                for (Object e : arr(v)) if (!devExt(e)) throw fail();
            } else if (!devExt(v)) throw fail();
        }
        infoWork = true;
    }

    private static boolean devExt(Object x) {
        if (!isDict(x) || !onlyKeys(dict(x), "Type", "BaseVersion", "ExtensionLevel", "ExtensionRevision", "URL")) return false;
        Map<String, Object> d = dict(x);
        if (!(dget(d, "BaseVersion") instanceof PName)) return false;
        if (!isInt(dget(d, "ExtensionLevel"))) return false;
        for (String k : List.of("ExtensionRevision", "URL")) if (d.containsKey(k) && !isStr(dget(d, k))) return false;
        if (d.containsKey("Type") && !ifaceEq(dget(d, "Type"), new PName("DeveloperExtensions"))) return false;
        return true;
    }

    void metadata(Object bv, Object fv) {
        if (pdfEqual(bv, fv) && (!(fv instanceof PRef) || !changed.contains(((PRef) fv).num))) return;
        if (!(fv instanceof PRef)) throw fail();
        Node mn = container(bv, fv, root, "metadata");
        if (!(mn.val instanceof PStream)) throw fail();
        Map<String, Object> sd = ((PStream) mn.val).dict;
        if (!onlyKeys(sd, "Type", "Subtype", "Length", "Filter", "DecodeParms") || !ifaceEq(dget(sd, "Type"), new PName("Metadata"))
            || !ifaceEq(dget(sd, "Subtype"), new PName("XML"))) {
            throw fail();
        }
        boolean[] bad = {false};
        pdfRefs(sd, x -> bad[0] = true);
        if (bad[0]) throw fail();
        if (isNew.contains(mn.num)) exclusive.add(mn.num);
        infoWork = true;
    }

    void info() {
        Object r = dget(fin.trailer, "Info");
        if (!(r instanceof PRef) || !changed.contains(((PRef) r).num) || isNew.contains(((PRef) r).num)) return;
        Object d = fin.get(((PRef) r).num);
        if (!isDict(d)) throw fail();
        for (Object v : dict(d).values()) if (!(v instanceof PStr) && !(v instanceof PName)) throw fail();
        claim(((PRef) r).num, "info");
        allowed.add(((PRef) r).num);
        infoWork = true;
    }
}
