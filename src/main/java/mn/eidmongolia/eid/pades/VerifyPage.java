package mn.eidmongolia.eid.pades;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** Fixed font asset (PAGE_SPEC §9): FontFile2 bytes as shipped (zlib, never re-compressed) + metrics. Immutable. */
final class PageFont {
    final String psName;
    final byte[] stream;
    final int length1;
    final int ascent;
    final int descent;
    final int capHeight;
    final int[] bbox;
    final int[] widths;
    final Map<Integer, Integer> gid;

    private PageFont(String psName, byte[] stream, int length1, int ascent, int descent, int capHeight, int[] bbox, int[] widths,
                     Map<Integer, Integer> gid) {
        this.psName = psName;
        this.stream = stream;
        this.length1 = length1;
        this.ascent = ascent;
        this.descent = descent;
        this.capHeight = capHeight;
        this.bbox = bbox;
        this.widths = widths;
        this.gid = gid;
    }

    int width1000(int g) {
        return widths[Math.min(g, widths.length - 1)];
    }

    private static int[] ints(List<Object> a) {
        int[] out = new int[a.size()];
        for (int i = 0; i < out.length; i++) out[i] = Math.toIntExact(((Json.Num) a.get(i)).longValue());
        return out;
    }

    @SuppressWarnings("unchecked")
    private static PageFont load(String base) {
        Json.Obj m = (Json.Obj) Json.parse(EidChain.resource("fonts/" + base + ".metrics.json"));
        List<Object> cm = m.getArr("cmap");
        Map<Integer, Integer> gid = new HashMap<>(cm.size() * 2);
        for (Object e : cm) {
            int[] pair = ints((List<Object>) e);
            gid.put(pair[0], pair[1]);
        }
        return new PageFont(m.getString("psName"), EidChain.resource("fonts/" + base + ".ttf.zlib"), m.getInt("length1"),
            m.getInt("ascent"), m.getInt("descent"), m.getInt("capHeight"), ints(m.getArr("bbox")), ints(m.getArr("widths")),
            Collections.unmodifiableMap(gid));
    }

    private static final class Holder {
        static final PageFont REGULAR = load("NotoSans-Regular");
        static final PageFont BOLD = load("NotoSans-Bold");
    }

    static PageFont regular() {
        return Holder.REGULAR;
    }

    static PageFont bold() {
        return Holder.BOLD;
    }
}

/** Verification page — PAGE_SPEC.md (Go reference `pades/internal/core/vpage.go`), byte for byte. */
final class VerifyPage {
    private VerifyPage() {
    }

    static final class Data {
        final String brand;
        final String fileName;
        final String documentHash;
        final long fileSize;
        final String docId;
        final String verifyUrl;
        final String trustUrl;
        final String caName;
        final String tsaName;
        final String provider;
        /** "mn" (default when null/empty) | "en" — PAGE_SPEC §3a. */
        final String lang;

        Data(String brand, String fileName, String documentHash, long fileSize, String docId, String verifyUrl, String trustUrl,
             String caName, String tsaName, String provider, String lang) {
            this.brand = brand;
            this.fileName = fileName;
            this.documentHash = documentHash;
            this.fileSize = fileSize;
            this.docId = docId;
            this.verifyUrl = verifyUrl;
            this.trustUrl = trustUrl;
            this.caName = caName;
            this.tsaName = tsaName;
            this.provider = provider;
            this.lang = lang;
        }
    }

    /** PAGE_SPEC §3a page texts. */
    private static final class Texts {
        final String title;
        final String subtitle;
        final String document;
        final String fileName;
        final String hashAlg;
        final String size;
        final String docHash;
        final String docId;
        final String verification;
        final String scan;
        final String scanHint;
        final String trust;
        final String provider;

        Texts(String title, String subtitle, String document, String fileName, String hashAlg, String size, String docHash, String docId,
              String verification, String scan, String scanHint, String trust, String provider) {
            this.title = title;
            this.subtitle = subtitle;
            this.document = document;
            this.fileName = fileName;
            this.hashAlg = hashAlg;
            this.size = size;
            this.docHash = docHash;
            this.docId = docId;
            this.verification = verification;
            this.scan = scan;
            this.scanHint = scanHint;
            this.trust = trust;
            this.provider = provider;
        }
    }

    private static final Map<String, Texts> TEXTS = Map.of(
        "mn", new Texts(
            "-аар гарын үсэг зурсан баримт",
            "Гарын үсгүүд энэ PDF-д шингэсэн. Доорх холбоосоор эсвэл Adobe Acrobat-ын Signatures самбараар шалгана уу.",
            "БАРИМТ", "БАРИМТЫН НЭР", "HASH АЛГОРИТМ", "ХЭМЖЭЭ",
            "БАРИМТЫН HASH", "БАРИМТЫН ID", "ШАЛГАХ", "Гарын үсгийг шалгах",
            "QR кодыг утасны камераар уншуулах эсвэл холбоосыг нээнэ үү.",
            "Adobe Acrobat-д Монгол Улсын үндэсний Root CA-д итгэх заавар:", "Үйлчилгээ"),
        "en", new Texts(
            " — Electronically signed document",
            "Signatures are embedded in this PDF. Verify them with the link below or in Adobe Acrobat's Signatures panel.",
            "DOCUMENT", "FILE NAME", "HASH ALGORITHM", "SIZE",
            "DOCUMENT HASH", "DOCUMENT ID", "VERIFICATION", "Scan to verify",
            "Scan this QR code with your phone camera to verify.",
            "Adobe Acrobat: trust the Mongolian National Root CA", "Provider"));

    private static final String MEDIA_BOX = "[0 0 595.28 841.89]";
    private static final int LEFT = 42;
    private static final int WIDTH = 510;
    private static final int COL2 = 297;
    private static final int QR_MODULE = 2;
    private static final int QR_TEXT_X = 136;
    private static final int FILE_NAME_MAX = 3;
    static final String TEXT = "0.118 0.118 0.118";
    static final String MUTED = "0.431 0.431 0.431";
    static final String OK = "0.086 0.541 0.31";
    private static final String BANNER = "0.863 0.961 0.902";
    private static final String LINE = "0.863 0.863 0.863";
    private static final String LINK = "0.118 0.431 0.863";
    private static final String BANNER_PATH = "48 800 m\n546 800 l\n549.31 800 552 797.31 552 794 c\n552 754 l\n552 750.69 549.31 748 546 748 c\n"
        + "48 748 l\n44.69 748 42 750.69 42 754 c\n42 794 l\n42 797.31 44.69 800 48 800 c\nh\nf";

    static final class Link {
        final int x1;
        final int y1;
        final int x2;
        final int y2;
        final String url;

        Link(int x1, int y1, int x2, int y2, String url) {
            this.x1 = x1;
            this.y1 = y1;
            this.x2 = x2;
            this.y2 = y2;
            this.url = url;
        }
    }

    static final class Writer {
        final PageFont reg;
        final PageFont bld;
        final StringBuilder ops = new StringBuilder();
        final List<Link> links = new ArrayList<>();

        Writer(PageFont reg, PageFont bld) {
            this.reg = reg;
            this.bld = bld;
        }

        void op(String s) {
            ops.append(s).append('\n');
        }

        PageFont font(int id) {
            return id == 2 ? bld : reg;
        }

        List<Integer> gids(int id, String s) {
            PageFont f = font(id);
            List<Integer> out = new ArrayList<>();
            for (int i = 0; i < s.length(); ) {
                int r = s.codePointAt(i);
                i += Character.charCount(r);
                Integer g = f.gid.get(r);
                out.add(g != null ? g : f.gid.get((int) '?'));
            }
            return out;
        }

        int width1000(int id, int size, String s) {
            if (id == 3) return 600 * s.codePointCount(0, s.length()) * size;
            int sum = 0;
            for (int g : gids(id, s)) sum += font(id).width1000(g);
            return sum * size;
        }

        void text(int id, int size, int x, int y, String color, String s) {
            String str = id == 3 ? "(" + s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") + ")" : glyphHex(id, s);
            op(color + " rg");
            op("BT /F" + id + " " + size + " Tf " + x + " " + y + " Td " + str + " Tj ET");
        }

        /** F1/F2 text `<GGGG…>` (PAGE_SPEC.md §2). */
        String glyphHex(int id, String s) {
            StringBuilder sb = new StringBuilder("<");
            for (int g : gids(id, s)) sb.append(String.format(Locale.ROOT, "%04X", g));
            return sb.append('>').toString();
        }

        void link(int id, int size, int x, int y, String s) {
            int wd = (width1000(id, size, s) + 999) / 1000;
            links.add(new Link(x, y - 3, x + wd, y + size, s));
        }

        void hline(int y) {
            op(LINE + " RG");
            op("0.75 w " + LEFT + " " + y + " m " + (LEFT + WIDTH) + " " + y + " l S");
        }

        List<String> wrap(int id, int size, String s, int maxW, int maxLines) {
            return wrapLimit(id, size, s, maxW * 1000, maxLines);
        }

        private boolean fits(int id, int size, String t, int limit) {
            return width1000(id, size, t) <= limit;
        }

        /** [wrap] with the width limit in 1/1000 pt (visible signature: 1/100 pt × 10). */
        List<String> wrapLimit(int id, int size, String s, int limit, int maxLines) {
            List<String> lines = new ArrayList<>();
            String cur = "";
            for (String w0 : s.split(" ", -1)) {
                String word = w0;
                if (word.isEmpty()) continue;
                String cand = cur.isEmpty() ? word : cur + " " + word;
                if (fits(id, size, cand, limit)) {
                    cur = cand;
                    continue;
                }
                if (!cur.isEmpty()) {
                    lines.add(cur);
                    cur = "";
                }
                while (!fits(id, size, word, limit)) {
                    int[] r = word.codePoints().toArray();
                    int n = 1;
                    while (n < r.length && fits(id, size, new String(r, 0, n + 1), limit)) n++;
                    lines.add(new String(r, 0, n));
                    word = new String(r, n, r.length - n);
                }
                cur = word;
            }
            if (!cur.isEmpty()) lines.add(cur);
            if (lines.size() > maxLines) {
                int[] last = lines.get(maxLines - 1).codePoints().toArray();
                int len = last.length;
                while (len > 0 && !fits(id, size, new String(last, 0, len) + "…", limit)) len--;
                List<String> out = new ArrayList<>(lines.subList(0, maxLines - 1));
                out.add(new String(last, 0, len) + "…");
                return out;
            }
            return lines;
        }
    }

    static String humanSize(long b) {
        if (b < (1L << 10)) return b + " B";
        if (b < (1L << 20)) return tenths(b, 1L << 10) + " KB";
        if (b < (1L << 30)) return tenths(b, 1L << 20) + " MB";
        return tenths(b, 1L << 30) + " GB";
    }

    private static String tenths(long b, long unit) {
        long t = (b * 10 + unit / 2) / unit;
        return (t / 10) + "." + (t % 10);
    }

    static String urlHost(String u) {
        String s = u;
        if (s.startsWith("https://")) s = s.substring(8);
        if (s.startsWith("http://")) s = s.substring(7);
        int i = s.indexOf('/');
        if (i > 0) {
            int next = s.indexOf('/', i + 1) - (i + 1);
            if (next > 0) return s.substring(0, i + 1 + next);
        }
        return s;
    }

    static boolean asciiUrl(String u) {
        if (u.isEmpty()) return false;
        for (int i = 0; i < u.length(); i++) {
            char c = u.charAt(i);
            if (c < 0x21 || c > 0x7e || c == '(' || c == ')' || c == '\\') return false;
        }
        return true;
    }

    private static byte[] content(Data p, Writer w) {
        if (!asciiUrl(p.verifyUrl) || !(p.trustUrl.isEmpty() || asciiUrl(p.trustUrl))) throw new IllegalArgumentException("URL is not ASCII");
        boolean[][] m = QrCode.encode(p.verifyUrl.getBytes(StandardCharsets.US_ASCII));
        String lang = p.lang == null || p.lang.isEmpty() ? "mn" : p.lang;
        Texts tx = TEXTS.get(lang);
        if (tx == null) throw new IllegalArgumentException("page language " + p.lang);
        w.op(BANNER + " rg");
        w.op(BANNER_PATH);
        w.text(2, 13, 56, 778, OK, p.brand + tx.title);
        w.text(1, 9, 56, 760, OK, tx.subtitle);
        int y = 724;
        w.hline(y);
        w.text(2, 11, LEFT, y - 17, TEXT, tx.document);
        y -= 34;
        w.text(1, 8, LEFT, y, MUTED, tx.fileName);
        y -= 14;
        List<String> fn = w.wrap(2, 10, p.fileName, WIDTH, FILE_NAME_MAX);
        for (int i = 0; i < fn.size(); i++) {
            if (i > 0) y -= 14;
            w.text(2, 10, LEFT, y, TEXT, fn.get(i));
        }
        y -= 20;
        w.text(1, 8, LEFT, y, MUTED, tx.hashAlg);
        w.text(1, 8, COL2, y, MUTED, tx.size);
        w.text(2, 10, LEFT, y - 14, TEXT, "SHA256");
        w.text(2, 10, COL2, y - 14, TEXT, humanSize(p.fileSize));
        y -= 34;
        w.text(1, 8, LEFT, y, MUTED, tx.docHash);
        w.text(3, 9, LEFT, y - 13, TEXT, p.documentHash);
        y -= 31;
        w.text(1, 8, LEFT, y, MUTED, tx.docId);
        w.text(3, 9, LEFT, y - 13, TEXT, p.docId);
        y -= 35;
        w.hline(y);
        w.text(2, 11, LEFT, y - 17, TEXT, tx.verification);
        y -= 35;
        w.text(1, 9, LEFT, y, LINK, p.verifyUrl);
        w.link(1, 9, LEFT, y, p.verifyUrl);
        y -= 14;
        w.op("0 0 0 rg");
        int n = m.length;
        for (int r = 0; r < n; r++) {
            int c = 0;
            while (c < n) {
                if (!m[r][c]) {
                    c++;
                    continue;
                }
                int s = c;
                while (c < n && m[r][c]) c++;
                w.op((LEFT + QR_MODULE * s) + " " + (y - QR_MODULE * (r + 1)) + " " + (QR_MODULE * (c - s)) + " " + QR_MODULE + " re");
            }
        }
        w.op("f");
        w.text(2, 11, QR_TEXT_X, y - 14, TEXT, tx.scan);
        w.text(1, 9, QR_TEXT_X, y - 29, MUTED, tx.scanHint);
        w.text(2, 9, QR_TEXT_X, y - 43, LINK, urlHost(p.verifyUrl));
        if (!p.trustUrl.isEmpty()) {
            w.text(1, 9, QR_TEXT_X, y - 60, MUTED, tx.trust);
            w.text(2, 9, QR_TEXT_X, y - 74, LINK, p.trustUrl);
            w.link(2, 9, QR_TEXT_X, y - 74, p.trustUrl);
        }
        w.hline(71);
        w.text(1, 8, LEFT, 58, MUTED, "CA: " + p.caName + "  |  TSA: " + p.tsaName + "  |  " + tx.provider + ": " + p.provider);
        return w.ops.toString().getBytes(StandardCharsets.UTF_8);
    }

    /** Adds the page as an incremental update: at the end of the root /Pages /Kids, at the front when [first] (PAGE_SPEC §8a). */
    static byte[] append(byte[] base, Data p, boolean first) {
        PageFont reg = PageFont.regular();
        PageFont bld = PageFont.bold();
        Writer w = new Writer(reg, bld);
        byte[] content = content(p, w);
        Incremental inc = new Incremental(base);
        PdfReader rd = inc.reader;
        PdfRef rootRef = rd.trailer.get("Root").ref();
        if (rootRef == null) throw new PdfException("Catalog is not an indirect object");
        PdfObj pagesRaw = inc.root().get("Pages");
        PdfRef pp = pagesRaw.ref();
        PdfDict pages = rd.resolve(pagesRaw).dict();
        if (pages == null || pp == null || !"Pages".equals(rd.get(pages, "Type").name()) || pp.equals(rootRef) || pp.id() == 0) {
            throw new PdfException("/Pages root missing");
        }
        Long cl = rd.get(pages, "Count").asLong();
        long count = cl == null ? 0 : cl;
        PdfObj kidsObj = rd.resolve(pages.get("Kids"));
        if (count < 0 || !(kidsObj instanceof PdfObj.Arr)) throw new PdfException("/Pages /Kids /Count invalid");
        List<PdfObj> kids = ((PdfObj.Arr) kidsObj).items();
        if (rootRef.gen() != 0) throw new PdfException("Catalog generation is not 0");
        int pageId = inc.reserve();
        int contentId = inc.reserve();
        int[][] fontIds = new int[2][5];
        for (int f = 0; f < 2; f++) for (int i = 0; i < 5; i++) fontIds[f][i] = inc.reserve();
        int courierId = inc.reserve();
        int[] linkIds = new int[w.links.size()];
        for (int i = 0; i < linkIds.length; i++) linkIds[i] = inc.reserve();

        StringBuilder pg = new StringBuilder("<< /Type /Page /Parent " + pp.id() + " " + pp.gen() + " R /MediaBox " + MEDIA_BOX
            + " /CropBox " + MEDIA_BOX + " /Rotate 0 ");
        pg.append("/Resources << /Font << /F1 ").append(fontIds[0][0]).append(" 0 R /F2 ").append(fontIds[1][0]).append(" 0 R /F3 ")
            .append(courierId).append(" 0 R >> >> /Contents ").append(contentId).append(" 0 R");
        if (linkIds.length > 0) {
            pg.append(" /Annots [");
            for (int i = 0; i < linkIds.length; i++) {
                if (i > 0) pg.append(' ');
                pg.append(linkIds[i]).append(" 0 R");
            }
            pg.append(']');
        }
        pg.append(" >>");
        inc.writeObject(pageId, Text.latin1(pg.toString()));
        inc.writeObject(contentId, streamObj("", content));
        writeFont(inc, fontIds[0], reg);
        writeFont(inc, fontIds[1], bld);
        inc.writeObject(courierId, Text.latin1("<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"));
        for (int i = 0; i < w.links.size(); i++) {
            Link l = w.links.get(i);
            inc.writeObject(linkIds[i], Text.latin1("<< /Type /Annot /Subtype /Link /Rect [" + l.x1 + " " + l.y1 + " " + l.x2 + " " + l.y2
                + "] /Border [0 0 0] /A << /S /URI /URI (" + l.url + ") >> >>"));
        }
        StringBuilder pn = new StringBuilder("<<");
        for (String key : pages.sortedKeys()) {
            if (key.equals("Kids") || key.equals("Count")) continue;
            pn.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(pages.get(key)));
        }
        pn.append(" /Kids [");
        if (first) {
            pn.append(pageId).append(" 0 R");
            for (PdfObj k : kids) pn.append(' ').append(inc.serialize(k));
            pn.append("] /Count ").append(count + 1).append(" >>");
        } else {
            for (PdfObj k : kids) pn.append(inc.serialize(k)).append(' ');
            pn.append(pageId).append(" 0 R] /Count ").append(count + 1).append(" >>");
        }
        inc.writeObject(pp.id(), Text.latin1(pn.toString()), pp.gen());
        return inc.finish(rootRef.id());
    }

    static byte[] streamObj(String extra, byte[] data) {
        return Der.concat(Text.latin1("<< /Length " + data.length + extra + " >>\nstream\n"), data, Text.latin1("\nendstream"));
    }

    private static void writeFont(Incremental inc, int[] ids, PageFont f) {
        List<byte[]> b = fontBodies(ids, f);
        for (int i = 0; i < b.size(); i++) inc.writeObject(ids[i], b.get(i));
    }

    /** [writeFont]'s 5 object bodies (in [ids] order) — shared by the verify page and the visible signature. */
    static List<byte[]> fontBodies(int[] ids, PageFont f) {
        StringBuilder wa = new StringBuilder();
        for (int i = 0; i < f.widths.length; i++) {
            if (i > 0) wa.append(' ');
            wa.append(f.width1000(i));
        }
        List<byte[]> out = new ArrayList<>();
        out.add(Text.latin1("<< /Type /Font /Subtype /Type0 /BaseFont /" + f.psName + " /Encoding /Identity-H /DescendantFonts [" + ids[1]
            + " 0 R] /ToUnicode " + ids[4] + " 0 R >>"));
        out.add(Text.latin1("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /" + f.psName + " /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) "
            + "/Supplement 0 >> /FontDescriptor " + ids[2] + " 0 R /CIDToGIDMap /Identity /W [0 [" + wa + "]] >>"));
        out.add(Text.latin1("<< /Type /FontDescriptor /FontName /" + f.psName + " /Flags 32 /FontBBox [" + f.bbox[0] + " " + f.bbox[1] + " "
            + f.bbox[2] + " " + f.bbox[3] + "] /ItalicAngle 0 /Ascent " + f.ascent + " /Descent " + f.descent + " /CapHeight " + f.capHeight
            + " /StemV 80 /FontFile2 " + ids[3] + " 0 R >>"));
        out.add(streamObj(" /Length1 " + f.length1 + " /Filter /FlateDecode", f.stream));
        out.add(streamObj("", toUnicode(f)));
        return out;
    }

    private static byte[] toUnicode(PageFont f) {
        Map<Integer, Integer> uni = new HashMap<>();
        for (Map.Entry<Integer, Integer> e : f.gid.entrySet()) {
            int r = e.getKey();
            int g = e.getValue();
            Integer old = uni.get(g);
            if (old == null || r < old) uni.put(g, r);
        }
        List<int[]> pairs = new ArrayList<>();
        for (int g = 0; g < f.widths.length; g++) {
            Integer r = uni.get(g);
            if (r != null) pairs.add(new int[] {g, r});
        }
        StringBuilder b = new StringBuilder("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n"
            + "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n"
            + "1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n");
        for (int i = 0; i < pairs.size(); i += 100) {
            List<int[]> chunk = pairs.subList(i, Math.min(pairs.size(), i + 100));
            b.append(chunk.size()).append(" beginbfchar\n");
            for (int[] gr : chunk) b.append(String.format(Locale.ROOT, "<%04X> <%04X>\n", gr[0], gr[1]));
            b.append("endbfchar\n");
        }
        b.append("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend");
        return b.toString().getBytes(StandardCharsets.US_ASCII);
    }
}
