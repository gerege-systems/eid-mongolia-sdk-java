package mn.eidmongolia.eid.pades.validate;

import static mn.eidmongolia.eid.pades.validate.PdfObjects.ent;
import static mn.eidmongolia.eid.pades.validate.PdfObjects.inUse;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStr;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PdfBudget;
import mn.eidmongolia.eid.pades.validate.PdfObjects.XrefSection;

/**
 * Analysis of the revisions added AFTER a signature: a 1:1 port of the TS SDK src/pades/validate/revisions.ts (Go SDK
 * pades/internal/validate/revisions.go). The document up to the end of the signed range (base) and the whole file are
 * compared as parsed object graphs; only when every difference is on the allow-list is the signature "extended by
 * signatures only". Everything else, including anything that fails to parse, is modified_after_signing (fail closed).
 * Profile "own" is the exact shape of our PAdES writer (prod); "broad" is the upper bound.
 */
final class Revisions {
    static final int MODE_BROAD = 0;
    static final int MODE_OWN = 1;
    static final int MODE_DSS_ONLY = 2;

    /** Sig dict free text (/Name /Reason /Location /ContactInfo /M) maximum length, bytes (Go ownTextLimit). */
    static final int OWN_TEXT_LIMIT = 256;

    private static final String[] OWN_TEXT_FORBIDDEN = {" obj", "endobj", "stream", "xref", "trailer", "startxref", "%%EOF"};

    final PdfBudget budget = new PdfBudget();
    final byte[] doc;
    /** Signatures parsed and cryptographically verified by extract: object number → ByteRange. */
    final Map<Integer, long[]> known;
    final String profile;
    final PadesSupport support;
    private final Map<Integer, PdfView> views = new HashMap<>();
    private final Map<String, LaterChanges> steps = new HashMap<>();
    Map<Integer, SigMeta> sigs = new LinkedHashMap<>();
    String docID = "";

    Revisions(byte[] doc, Map<Integer, long[]> known, String profile, PadesSupport support) {
        this.doc = doc;
        this.known = known;
        this.profile = profile;
        this.support = support;
    }

    PdfView view(int n) {
        if (views.containsKey(n)) return views.get(n);
        PdfView v;
        try {
            v = PdfView.open(doc, n, budget);
        } catch (RuntimeException e) {
            v = null;
        }
        views.put(n, v);
        return v;
    }

    /** Classifies the changes after signedEnd (ByteRange end). Any failure is "not allowed". */
    LaterChanges later(long signedEnd) {
        try {
            return laterSync(signedEnd);
        } catch (RuntimeException | StackOverflowError e) {
            return LaterChanges.NOTHING;
        }
    }

    private LaterChanges laterSync(long signedEnd) {
        int n = doc.length;
        if (signedEnd <= 0 || signedEnd >= n) return LaterChanges.NOTHING;
        int end = (int) signedEnd;
        PdfView fin = view(n);
        PdfView base = view(end);
        if (fin == null || base == null) return LaterChanges.NOTHING;
        int k = fin.sections.size() - base.sections.size();
        if (k < 1) return LaterChanges.NOTHING;
        List<Integer> ends = new ArrayList<>();
        ends.add(end);
        for (int i = k - 1; i >= 0; i--) {
            XrefSection s = fin.sections.get(i);
            PdfParser p = fin.parser(s.end);
            long at = p.startxref();
            int e = p.pos;
            if (i == 0) e = n;
            if (at < 0 || at != s.off || e <= ends.get(ends.size() - 1)) return LaterChanges.NOTHING;
            ends.add(e);
        }
        int signatures = 0;
        boolean visible = false;
        int sigSteps = 0;
        for (int i = 1; i < ends.size(); i++) {
            boolean hasSig = hasSig(ends.get(i - 1), ends.get(i));
            if (hasSig) sigSteps++;
            LaterChanges st = classify(ends.get(i - 1), ends.get(i), true, stepMode(hasSig));
            if (st == null) return LaterChanges.NOTHING;
            signatures += st.signatures;
            visible = visible || st.visible;
        }
        if (k > 1) {
            int mode = MODE_BROAD;
            if (sigSteps == k) mode = stepMode(true);
            else if (sigSteps == 0) mode = stepMode(false);
            LaterChanges cum = classify(ends.get(0), n, false, mode);
            if (cum == null || cum.signatures != signatures) return LaterChanges.NOTHING;
            visible = visible || cum.visible;
        }
        return new LaterChanges(true, signatures, visible);
    }

    private int stepMode(boolean hasSig) {
        if (!hasSig) return MODE_DSS_ONLY;
        if (profile.equals("own")) return MODE_OWN;
        return MODE_BROAD;
    }

    private boolean hasSig(int from, int to) {
        PdfView base = view(from);
        PdfView fin = view(to);
        if (base == null || fin == null) return true;
        for (int num : known.keySet()) {
            if (inUse(ent(fin.xref, num)) && !inUse(ent(base.xref, num))) return true;
        }
        return false;
    }

    private LaterChanges classify(int from, int to, boolean strict, int mode) {
        String key = from + "," + to + "," + (mode * 2 + (strict ? 1 : 0));
        if (steps.containsKey(key)) return steps.get(key);
        LaterChanges res = null;
        PdfView base = view(from);
        PdfView fin = view(to);
        if (base != null && fin != null) {
            Classifier c = new Classifier(base, fin, strict, known, support);
            c.sigs = sigs;
            c.docID = docID;
            c.own = mode == MODE_OWN;
            c.dssOnly = mode == MODE_DSS_ONLY;
            c.ownProfile = profile.equals("own");
            boolean ok = true;
            try {
                c.run();
            } catch (PdfObjError e) {
                // Any other exception is a Go panic: it propagates to later() and is not cached.
                ok = false;
            }
            if (ok) res = new LaterChanges(true, c.sigDicts.size(), c.visible);
        }
        steps.put(key, res);
        return res;
    }

    // ── text helpers (TS revisions.ts) ──

    /** Go string(utf16.Decode(units)): an unpaired surrogate → U+FFFD. */
    private static String decodeUTF16(List<Integer> units) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < units.size(); i++) {
            int u = units.get(i);
            if (u >= 0xd800 && u < 0xdc00 && i + 1 < units.size() && units.get(i + 1) >= 0xdc00 && units.get(i + 1) < 0xe000) {
                out.appendCodePoint(0x10000 + ((u - 0xd800) << 10) + (units.get(i + 1) - 0xdc00));
                i++;
            } else if (u >= 0xd800 && u < 0xe000) out.append('�');
            else out.append((char) u);
        }
        return out.toString();
    }

    /** Go UTF-8 rune iteration over raw bytes (each invalid byte is one U+FFFD). */
    static String goUTF8(String raw) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < raw.length();) {
            int c = raw.charAt(i);
            if (c < 0x80) {
                out.append((char) c);
                i++;
                continue;
            }
            int n = 0;
            int cp = 0;
            int lo = 0x80;
            int hi = 0xbf;
            if (c >= 0xc2 && c <= 0xdf) {
                n = 1;
                cp = c & 0x1f;
            } else if (c >= 0xe0 && c <= 0xef) {
                n = 2;
                cp = c & 0x0f;
                if (c == 0xe0) lo = 0xa0;
                if (c == 0xed) hi = 0x9f;
            } else if (c >= 0xf0 && c <= 0xf4) {
                n = 3;
                cp = c & 0x07;
                if (c == 0xf0) lo = 0x90;
                if (c == 0xf4) hi = 0x8f;
            }
            boolean ok = n > 0 && i + n < raw.length();
            if (ok) {
                for (int k = 1; k <= n; k++) {
                    int x = raw.charAt(i + k);
                    int l = k == 1 ? lo : 0x80;
                    int h = k == 1 ? hi : 0xbf;
                    if (x < l || x > h) {
                        ok = false;
                        break;
                    }
                    cp = (cp << 6) | (x & 0x3f);
                }
            }
            if (!ok) {
                out.append('�');
                i++;
                continue;
            }
            out.appendCodePoint(cp);
            i += n + 1;
        }
        return out.toString();
    }

    /** PDF text string: UTF-16BE with a FE FF BOM, else raw bytes read as UTF-8 (Go string). */
    static String pdfTextString(PStr s) {
        String raw = s.v;
        if (!raw.startsWith("þÿ")) return goUTF8(raw);
        List<Integer> units = new ArrayList<>();
        for (int i = 2; i + 1 < raw.length(); i += 2) units.add((raw.charAt(i) << 8) | raw.charAt(i + 1));
        return decodeUTF16(units);
    }

    /** v is text in the shape digitorus pdfString writes; the decoded text, or null. */
    static String ownText(Object v, int limit) {
        if (!(v instanceof PStr) || ((PStr) v).v.length() > limit) return null;
        String raw = ((PStr) v).v;
        boolean utf16be = raw.startsWith("þÿ");
        if (utf16be && raw.length() % 2 != 0) return null;
        String text = pdfTextString((PStr) v);
        int[] cps = text.codePoints().toArray();
        for (int r : cps) {
            if (r < 0x20 || r == 0x7f || (!utf16be && r > 0x7e)) return null;
        }
        for (String bad : OWN_TEXT_FORBIDDEN) if (raw.contains(bad) || text.contains(bad)) return null;
        return text;
    }

    /** "D:YYYYMMDDHHmmSS±HH'mm'". */
    static boolean ownDate(String s) {
        if (s.length() != 23 || !s.startsWith("D:") || (s.charAt(16) != '+' && s.charAt(16) != '-') || s.charAt(19) != '\''
            || s.charAt(22) != '\'') {
            return false;
        }
        String d = s.substring(2, 16) + s.substring(17, 19) + s.substring(20, 22);
        for (int i = 0; i < d.length(); i++) if (d.charAt(i) < '0' || d.charAt(i) > '9') return false;
        return true;
    }
}
