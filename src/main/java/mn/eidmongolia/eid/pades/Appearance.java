package mn.eidmongolia.eid.pades;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/** Visible signature placement / size / page invalid or the text does not fit (→ REQUEST_INVALID). */
final class AppearanceException extends RuntimeException {
    AppearanceException(String msg) {
        super(msg);
    }
}

/**
 * Visible signature — APPEARANCE_SPEC.md (pades-client/1), 1:1 port of Go reference `pades/internal/core/appearance.go`.
 * The widget sits on the chosen page with a /Rect; /AP /N is an uncompressed form XObject (verify-page font assets, own
 * QR). Every length/coordinate is an integer in 1/100 pt (h100), written with [num100].
 */
final class Appearance {
    private Appearance() {
    }

    /** prepareSignature's visible input: placement (displayed page space, h100) and texts. [page] is 1-based, resolved. */
    static final class Visible {
        final int page;
        final long x;
        final long y;
        final long w;
        final long h;
        final String name;
        final String role;
        final String lang;
        /** «YYYY-MM-DD HH:MM (+08)» */
        final String date;
        /** https://ca.eidmongolia.mn/verify/<docId>/<revIndex> */
        final String url;
        /** PLACEMENT_SPEC §6a: never move the stamp; the scan only reports OVERLAP. */
        final boolean exact;

        Visible(int page, long x, long y, long w, long h, String name, String role, String lang, String date, String url, boolean exact) {
            this.page = page;
            this.x = x;
            this.y = y;
            this.w = w;
            this.h = h;
            this.name = name;
            this.role = role;
            this.lang = lang;
            this.date = date;
            this.url = url;
            this.exact = exact;
        }

        Visible onPage(int p) {
            return new Visible(p, x, y, w, h, name, role, lang, date, url, exact);
        }
    }

    /** Form XObject input: displayed (post-rotation) width/height in h100, page /Rotate 0|90|180|270. */
    static final class Params {
        final int w;
        final int h;
        final int rotate;
        final String name;
        final String role;
        final String lang;
        final String date;
        final String url;

        Params(int w, int h, int rotate, String name, String role, String lang, String date, String url) {
            this.w = w;
            this.h = h;
            this.rotate = rotate;
            this.name = name;
            this.role = role;
            this.lang = lang;
            this.date = date;
            this.url = url;
        }
    }

    private static final int PAD = 400;
    private static final int GAP = 400;
    private static final int MIN_MODULE = 100;
    private static final int MAX_SIZE = 11;
    private static final int MIN_SIZE = 7;
    private static final int BODY_DELTA = 2;
    private static final int LEADING = 125;
    private static final int DESCENT = 25;
    private static final int MAX_LINES = 2;
    private static final int MAX_DEPTH = 32;

    /** Max width/height (14400 pt), h100. */
    static final int MAX_SIDE = 1440000;

    private static final Map<String, String> LABELS = Map.of("mn", "eID Mongolia-аар зурсан", "en", "Signed with eID Mongolia");

    /** pt → h100: floor(v × 100 + 0.5). */
    static long round100(double v) {
        return (long) Math.floor(v * 100 + 0.5);
    }

    /** h100 → PDF number: «N», «N.d», «N.dd» (no trailing zero), «-» when negative. */
    static String num100(long v0) {
        long v = v0;
        StringBuilder sb = new StringBuilder();
        if (v < 0) {
            sb.append('-');
            v = -v;
        }
        sb.append(v / 100);
        long f = v % 100;
        if (f != 0) {
            sb.append('.');
            if (f % 10 == 0) sb.append(f / 10);
            else if (f < 10) sb.append('0').append(f);
            else sb.append(f);
        }
        return sb.toString();
    }

    private static final class Rotation {
        final String cm;
        final int bw;
        final int bh;

        Rotation(String cm, int bw, int bh) {
            this.cm = cm;
            this.bw = bw;
            this.bh = bh;
        }
    }

    private static Rotation rotation(int rot, int w, int h) {
        switch (rot) {
            case 0:
                return new Rotation("", w, h);
            case 90:
                return new Rotation("0 1 -1 0 " + num100(h) + " 0 cm", h, w);
            case 180:
                return new Rotation("-1 0 0 -1 " + num100(w) + " " + num100(h) + " cm", w, h);
            case 270:
                return new Rotation("0 -1 1 0 0 " + num100(w) + " cm", h, w);
            default:
                throw new AppearanceException("/Rotate " + rot);
        }
    }

    private static final class Line {
        final int font;
        final int size;
        final String color;
        final String text;

        Line(int font, int size, String color, String text) {
            this.font = font;
            this.size = size;
            this.color = color;
            this.text = text;
        }
    }

    /** Form XObject content stream (APPEARANCE_SPEC.md §3). */
    static byte[] content(Params p) {
        String label = LABELS.get(p.lang);
        if (label == null) throw new AppearanceException("language " + p.lang);
        if (!VerifyPage.asciiUrl(p.url)) throw new AppearanceException("URL is not ASCII");
        if (p.w <= 0 || p.h <= 0 || p.w > MAX_SIDE || p.h > MAX_SIDE) throw new AppearanceException("size");
        boolean[][] m;
        try {
            m = QrCode.encode(p.url.getBytes(StandardCharsets.US_ASCII));
        } catch (Exception e) {
            throw new AppearanceException(e.getMessage() == null ? "QR" : e.getMessage());
        }
        int n = m.length;
        int mod = (p.h - 2 * PAD) / n;
        if (mod < MIN_MODULE) throw new AppearanceException("too small (height ≥ " + num100(2 * PAD + n * MIN_MODULE) + " pt)");
        int tx = PAD + mod * n + GAP;
        int tw = p.w - tx - PAD;
        VerifyPage.Writer w = new VerifyPage.Writer(PageFont.regular(), PageFont.bold());
        List<Line> lines = null;
        int f = MAX_SIZE;
        while (f >= MIN_SIZE && lines == null && tw > 0) {
            lines = layout(w, p, label, f, tw);
            f--;
        }
        if (lines == null) throw new AppearanceException("too small (text does not fit)");
        int total = 0;
        for (Line l : lines) total += l.size * LEADING;
        String cm = rotation(p.rotate, p.w, p.h).cm;
        w.op("/EIDVerify <</URL (" + p.url + ")>> BDC");
        if (!cm.isEmpty()) {
            w.op("q");
            w.op(cm);
        }
        w.op(VerifyPage.OK + " RG");
        w.op("1 w");
        w.op("0.5 0.5 " + num100(p.w - 100) + " " + num100(p.h - 100) + " re S");
        w.op("q " + num100(mod) + " 0 0 " + num100(mod) + " " + num100(PAD) + " " + num100((p.h - mod * n) / 2) + " cm");
        w.op("0 0 0 rg");
        for (int r = 0; r < n; r++) {
            int c = 0;
            while (c < n) {
                if (!m[r][c]) {
                    c++;
                    continue;
                }
                int s = c;
                while (c < n && m[r][c]) c++;
                w.op(s + " " + (n - 1 - r) + " " + (c - s) + " 1 re");
            }
        }
        w.op("f");
        w.op("Q");
        int cursor = p.h - PAD - (p.h - 2 * PAD - total) / 2;
        for (Line l : lines) {
            cursor -= l.size * LEADING;
            w.op(l.color + " rg");
            w.op("BT /F" + l.font + " " + l.size + " Tf " + num100(tx) + " " + num100(cursor + l.size * DESCENT) + " Td "
                + w.glyphHex(l.font, l.text) + " Tj ET");
        }
        if (!cm.isEmpty()) w.op("Q");
        w.op("EMC");
        return w.ops.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static List<Line> layout(VerifyPage.Writer w, Params p, String label, int f, int tw) {
        int b = f - BODY_DELTA;
        int limit = tw * 10;
        List<Line> lines = new ArrayList<>();
        for (String t : w.wrapLimit(2, f, p.name, limit, MAX_LINES)) lines.add(new Line(2, f, VerifyPage.TEXT, t));
        if (!p.role.isEmpty()) for (String t : w.wrapLimit(1, b, p.role, limit, MAX_LINES)) lines.add(new Line(1, b, VerifyPage.TEXT, t));
        lines.add(new Line(1, b, VerifyPage.OK, label));
        lines.add(new Line(1, b, VerifyPage.MUTED, p.date));
        int total = 0;
        for (Line l : lines) {
            if (l.text.isEmpty() || w.width1000(l.font, l.size, l.text) > limit) return null;
            total += l.size * LEADING;
        }
        if (total > p.h - 2 * PAD) return null;
        return lines;
    }

    /** /AP /N form XObject and its 2 fonts (11 objects): ids = [form, F1 ×5, F2 ×5]; returns the bodies in that order. */
    static List<byte[]> objects(Params p, int[] ids) {
        Rotation rot = rotation(p.rotate, p.w, p.h);
        byte[] content = content(p);
        byte[] form = VerifyPage.streamObj(" /Type /XObject /Subtype /Form /BBox [0 0 " + num100(rot.bw) + " " + num100(rot.bh)
            + "] /Resources << /Font << /F1 " + ids[1] + " 0 R /F2 " + ids[6] + " 0 R >> >>", content);
        List<byte[]> out = new ArrayList<>();
        out.add(form);
        out.addAll(VerifyPage.fontBodies(Arrays.copyOfRange(ids, 1, 6), PageFont.regular()));
        out.addAll(VerifyPage.fontBodies(Arrays.copyOfRange(ids, 6, 11), PageFont.bold()));
        return out;
    }

    /** Visible signature field/widget body (APPEARANCE_SPEC.md §2); [rect] in user space (h100). */
    static byte[] widget(String fieldName, long[] rect, PdfRef page, int sigId, int formId) {
        String r = num100(rect[0]) + " " + num100(rect[1]) + " " + num100(rect[2]) + " " + num100(rect[3]);
        return ("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [" + r + "]\n  /P " + page.id() + " " + page.gen() + " R\n"
            + "  /F 4\n  /FT /Sig\n  /T (" + fieldName + ")\n  /V " + sigId + " 0 R\n  /AP << /N " + formId + " 0 R >>\n>>")
            .getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Displayed (x, y, w, h) → user-space /Rect (APPEARANCE_SPEC.md §1). */
    static long[] rect(long[] box, int rot, long x, long y, long w, long h) {
        long b0 = box[0];
        long b1 = box[1];
        long b2 = box[2];
        long b3 = box[3];
        long bw = b2 - b0;
        long bh = b3 - b1;
        long vw = rot == 90 || rot == 270 ? bh : bw;
        long vh = rot == 90 || rot == 270 ? bw : bh;
        if (x < 0 || y < 0 || w <= 0 || h <= 0 || x + w > vw || y + h > vh) throw new AppearanceException("rectangle outside the page (CropBox)");
        long[] p1 = pt(box, rot, x, y);
        long[] p2 = pt(box, rot, x + w, y + h);
        return new long[] {Math.min(p1[0], p2[0]), Math.min(p1[1], p2[1]), Math.max(p1[0], p2[0]), Math.max(p1[1], p2[1])};
    }

    private static long[] pt(long[] box, int rot, long vx, long vy) {
        switch (rot) {
            case 90:
                return new long[] {box[2] - vy, box[1] + vx};
            case 180:
                return new long[] {box[2] - vx, box[3] - vy};
            case 270:
                return new long[] {box[0] + vy, box[3] - vx};
            default:
                return new long[] {box[0] + vx, box[1] + vy};
        }
    }

    static final class Geometry {
        final long[] box;
        final int rot;

        Geometry(long[] box, int rot) {
            this.box = box;
            this.rot = rot;
        }
    }

    private static PdfObj inherited(PdfReader rd, PdfDict page, String key) {
        PdfDict v = page;
        for (int i = 0; i < MAX_DEPTH; i++) {
            PdfObj x = rd.get(v, key);
            if (!x.isNull()) return x;
            PdfObj parent = rd.get(v, "Parent");
            if (!(parent instanceof PdfObj.Dict)) return null;
            v = ((PdfObj.Dict) parent).d();
        }
        return null;
    }

    /** Page's (inherited) CropBox, else MediaBox, normalised in h100, and /Rotate (0–270). */
    static Geometry geometry(PdfReader rd, PdfDict page) {
        PdfObj bo = inherited(rd, page, "CropBox");
        if (bo == null) bo = inherited(rd, page, "MediaBox");
        if (!(bo instanceof PdfObj.Arr) || ((PdfObj.Arr) bo).items().size() != 4) throw new AppearanceException("page MediaBox missing");
        List<PdfObj> items = ((PdfObj.Arr) bo).items();
        long[] f = new long[4];
        for (int i = 0; i < 4; i++) {
            PdfObj e = rd.resolve(items.get(i));
            double v;
            if (e instanceof PdfObj.Int) v = ((PdfObj.Int) e).v();
            else if (e instanceof PdfObj.Real) v = ((PdfObj.Real) e).v();
            else throw new AppearanceException("page box invalid");
            if (!Double.isFinite(v) || Math.abs(v) > 1e7) throw new AppearanceException("page box invalid");
            f[i] = round100(v);
        }
        long[] box = {Math.min(f[0], f[2]), Math.min(f[1], f[3]), Math.max(f[0], f[2]), Math.max(f[1], f[3])};
        int rot = 0;
        PdfObj r = inherited(rd, page, "Rotate");
        if (r != null) {
            if (!(r instanceof PdfObj.Int) || ((PdfObj.Int) r).v() % 90 != 0) throw new AppearanceException("page /Rotate is not a multiple of 90");
            rot = (int) (((((PdfObj.Int) r).v() % 360) + 360) % 360);
        }
        return new Geometry(box, rot);
    }

    /** n-th (1-based) /Page of the /Pages tree in tree order (depth ≤ 32) + the reference it was reached by: {PdfDict, PdfRef}. */
    static Object[] nthPage(PdfReader rd, PdfObj pages, PdfRef owner, int n0) {
        if (n0 < 1) return null;
        int[] n = {n0};
        return walkNth(rd, pages, owner, 0, n);
    }

    private static Object[] walkNth(PdfReader rd, PdfObj v, PdfRef owner, int depth, int[] n) {
        if (depth > MAX_DEPTH) return null;
        PdfRef ref = v.ref() != null ? v.ref() : owner;
        PdfDict d = rd.resolve(v).dict();
        if (d == null) return null;
        String t = rd.get(d, "Type").name();
        if ("Page".equals(t)) {
            n[0]--;
            return n[0] == 0 && ref != null ? new Object[] {d, ref} : null;
        }
        if ("Pages".equals(t)) {
            PdfObj kids = rd.get(d, "Kids");
            if (!(kids instanceof PdfObj.Arr)) return null;
            for (PdfObj kid : ((PdfObj.Arr) kids).items()) {
                Object[] p = walkNth(rd, kid, ref, depth + 1, n);
                if (p != null) return p;
                if (n[0] <= 0) break;
            }
        }
        return null;
    }

    /**
     * Go `core.DefaultStampPage` (PLACEMENT_SPEC §1a): the page for `appearance.page` 0 — the last page (tree order) that
     * is not an eID verify page — and the page count n: {page, n}.
     */
    static int[] defaultStampPage(byte[] doc, String verifyUri) {
        Incremental inc = new Incremental(doc);
        List<PdfDict> pages = pageList(inc.reader, inc.root().get("Pages"));
        return new int[] {lastContentPage(inc.reader, pages, verifyUri), pages.size()};
    }

    private static int lastContentPage(PdfReader rd, List<PdfDict> pages, String verifyUri) {
        for (int i = pages.size() - 1; i >= 0; i--) {
            if (verifyUri.isEmpty() || !isVerifyPage(rd, pages.get(i), verifyUri)) return i + 1;
        }
        return pages.size();
    }

    /** Go `pageList`: the /Page dictionaries in /Pages tree order (depth ≤ 32, at most 65 537). */
    private static List<PdfDict> pageList(PdfReader rd, PdfObj root) {
        List<PdfDict> pages = new ArrayList<>();
        walkPages(rd, root, 0, pages);
        return pages;
    }

    private static void walkPages(PdfReader rd, PdfObj v, int depth, List<PdfDict> pages) {
        if (depth > MAX_DEPTH || pages.size() > (1 << 16)) return;
        PdfDict d = rd.resolve(v).dict();
        if (d == null) return;
        String t = rd.get(d, "Type").name();
        if ("Page".equals(t)) {
            pages.add(d);
        } else if ("Pages".equals(t)) {
            PdfObj kids = rd.get(d, "Kids");
            if (kids instanceof PdfObj.Arr) for (PdfObj k : ((PdfObj.Arr) kids).items()) walkPages(rd, k, depth + 1, pages);
        }
    }

    /** [suggest]'s result: resolved page, the choice, and every page's visible {w, h} in h100 (null = unreadable). */
    static final class Suggested {
        final int page;
        final StampPlacement.Result result;
        final List<long[]> sizes;

        Suggested(int page, StampPlacement.Result result, List<long[]> sizes) {
            this.page = page;
            this.result = result;
            this.sizes = sizes;
        }
    }

    /**
     * Go `core.SuggestVisible` (PLACEMENT_SPEC §6b): the placement [SignatureRevision.prepare] would choose, without
     * writing anything. Request errors are [AppearanceException]; anything else is a PDF error.
     */
    static Suggested suggest(byte[] doc, String verifyUri, int page0, long x, long y, long w, long h, boolean exact) {
        Incremental inc = new Incremental(doc);
        PdfReader rd = inc.reader;
        List<PdfDict> pages = pageList(rd, inc.root().get("Pages"));
        int n = pages.size();
        int page = page0 == 0 ? lastContentPage(rd, pages, verifyUri) : page0;
        if (page < 1 || page > n) throw new AppearanceException("page " + page + " > page count " + n);
        List<long[]> sizes = new ArrayList<>();
        for (PdfDict d : pages) {
            try {
                Geometry g = geometry(rd, d);
                long bw = g.box[2] - g.box[0];
                long bh = g.box[3] - g.box[1];
                sizes.add(g.rot == 90 || g.rot == 270 ? new long[] {bh, bw} : new long[] {bw, bh});
            } catch (Exception e) {
                sizes.add(null);
            }
        }
        StampPlacement.Located loc = StampPlacement.locate(rd, inc.root().get("Pages"), rd.trailer.get("Root").ref(), page, x, y, w, h, exact);
        return new Suggested(page, loc.result, sizes);
    }

    /** Go `isVerifyPage`: /Annots (first 10 000) holds a /Link whose /A is `/S /URI` with /URI byte-equal to verifyUri. */
    static boolean isVerifyPage(PdfReader rd, PdfDict page, String verifyUri) {
        byte[] want = verifyUri.getBytes(StandardCharsets.US_ASCII);
        PdfObj annots;
        try {
            annots = rd.get(page, "Annots");
        } catch (Exception e) {
            return false;
        }
        if (!(annots instanceof PdfObj.Arr)) return false;
        List<PdfObj> items = ((PdfObj.Arr) annots).items();
        for (int i = 0; i < Math.min(items.size(), 10_000); i++) {
            try {
                PdfDict a = rd.resolve(items.get(i)).dict();
                if (a == null || !"Link".equals(rd.get(a, "Subtype").name())) continue;
                PdfDict act = rd.get(a, "A").dict();
                if (act == null || !"URI".equals(rd.get(act, "S").name())) continue;
                PdfObj uri = rd.get(act, "URI");
                if (uri instanceof PdfObj.Str && Arrays.equals(((PdfObj.Str) uri).bytes(), want)) return true;
            } catch (Exception e) {
                // unreadable annotation — not a verify link
            }
        }
        return false;
    }
}
