package mn.eidmongolia.eid.pades;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;

/** Go reference `pades/internal/core/signature.go`: the signature revision (R_sig), CMS embedding, text strings. */
final class SignatureRevision {
    /** /Contents capacity in CMS bytes (2 × measured max 14 KiB); file holds 2× hex chars. */
    static final int PLACEHOLDER_BYTES = 2 * (14 << 10);
    static final String SUB_FILTER = "ETSI.CAdES.detached";
    private static final int BYTE_RANGE_WIDTH = 40;
    static final int REASON_MAX_UNITS = 127;
    private static final String[] KEYWORDS = {" obj", "endobj", "stream", "xref", "trailer", "%%EOF"};

    private SignatureRevision() {
    }

    /** [placement] — the visible stamp's final position (null for an invisible signature), PLACEMENT_SPEC.md. */
    static final class Prepared {
        final byte[] pdf;
        final long[] byteRange;
        final byte[] digest;
        final String fieldName;
        final StampPlacement.Result placement;

        Prepared(byte[] pdf, long[] byteRange, byte[] digest, String fieldName, StampPlacement.Result placement) {
            this.pdf = pdf;
            this.byteRange = byteRange;
            this.digest = digest;
            this.fieldName = fieldName;
            this.placement = placement;
        }
    }

    static final class PlaceholderOverflow extends RuntimeException {
        PlaceholderOverflow(String msg) {
            super(msg);
        }
    }

    /**
     * Approval signature revision: Sig dict + placeholder, widget, new Catalog/AcroForm. Without [vis] the widget is
     * invisible on the first page; with [vis] (APPEARANCE_SPEC.md) it has a /Rect on page [vis.page], /F 4 and an /AP /N
     * form XObject (+ 2 fonts), appended to that page's /Annots. [vis.name] must equal the written /Name, else
     * [AppearanceException].
     */
    static Prepared prepare(byte[] base, Date signingTime, String signerName, String reason, Appearance.Visible vis)
        throws AppearanceException {
        Incremental inc = new Incremental(base);
        PdfReader rd = inc.reader;
        PdfDict root = inc.root();
        PdfObj acroObj = rd.get(root, "AcroForm");
        PdfDict acro = acroObj.dict();
        PdfObj fieldsObj = acro != null ? rd.get(acro, "Fields") : PdfObj.NULL;
        List<PdfObj> fields = fieldsObj instanceof PdfObj.Arr ? ((PdfObj.Arr) fieldsObj).items() : Collections.emptyList();
        Set<String> names = new HashSet<>();
        int sigFields = 0;
        for (PdfObj f : fields) {
            PdfDict fd = rd.resolve(f).dict();
            if (fd == null) continue;
            names.add(text(rd.get(fd, "T")));
            if ("Sig".equals(rd.get(fd, "FT").name())) sigFields++;
        }
        int k = sigFields + 1;
        while (names.contains("Signature " + k)) k++;
        String fieldName = "Signature " + k;

        int sigId = inc.reserve();
        int fieldId = inc.reserve();
        int catId = inc.reserve();
        int[] apIds = new int[vis != null ? 11 : 0]; // form, F1 ×5, F2 ×5
        for (int i = 0; i < apIds.length; i++) apIds[i] = inc.reserve();

        // ── Sig dict (placeholder) ──
        StringBuilder sig = new StringBuilder("<<\n /Type /Sig\n /Filter /Adobe.PPKLite\n /SubFilter /" + SUB_FILTER + "\n /ByteRange ");
        int brAt = sig.length();
        for (int i = 0; i < BYTE_RANGE_WIDTH; i++) sig.append(' ');
        sig.append("\n /Contents <");
        int contentsAt = sig.length() - 1;
        for (int i = 0; i < 2 * PLACEHOLDER_BYTES; i++) sig.append('0');
        sig.append(">\n /M ").append(pdfDate(signingTime));
        String nm = sigText(signerName, 120);
        if (nm != null) sig.append("\n /Name ").append(nm);
        String rs = sigText(reason == null ? "" : reason, REASON_MAX_UNITS);
        if (rs != null) sig.append("\n /Reason ").append(rs);
        sig.append("\n>>");
        int sigStart = inc.writeObject(sigId, Text.latin1(sig.toString()));

        // ── field + widget ──
        Object[] page; // {PdfDict, PdfRef}
        StampPlacement.Result placement = null;
        if (vis == null) {
            // Invisible (digitorus createVisualSignature, invisible): first page.
            StringBuilder fld = new StringBuilder("<<\n  /Type /Annot\n  /Subtype /Widget\n  /Rect [0 0 0 0]\n");
            page = firstPage(rd, root.get("Pages"), rd.trailer.get("Root").ref(), 0);
            if (page != null) {
                PdfRef pr = (PdfRef) page[1];
                fld.append("  /P ").append(pr.id()).append(' ').append(pr.gen()).append(" R\n");
            }
            fld.append("  /F 132\n  /FT /Sig\n  /T (").append(fieldName).append(")\n  /V ").append(sigId).append(" 0 R\n>>");
            inc.writeObject(fieldId, Text.latin1(fld.toString()));
        } else {
            if (nm == null || !Text.trimSpace(signerName).equals(vis.name)) throw new AppearanceException("name cannot be written to /Name");
            StampPlacement.Located loc = StampPlacement.locate(rd, root.get("Pages"), rd.trailer.get("Root").ref(), vis.page, vis.x, vis.y,
                vis.w, vis.h, vis.exact);
            page = new Object[] {loc.page, loc.pageRef};
            placement = loc.result;
            List<byte[]> bodies = Appearance.objects(
                new Appearance.Params((int) vis.w, (int) vis.h, loc.rot, vis.name, vis.role, vis.lang, vis.date, vis.url), apIds);
            inc.writeObject(fieldId, Appearance.widget(fieldName, loc.rect, loc.pageRef, sigId, apIds[0]));
            for (int i = 0; i < bodies.size(); i++) inc.writeObject(apIds[i], bodies.get(i));
        }
        if (page != null) addWidgetToPage(inc, (PdfDict) page[0], (PdfRef) page[1], fieldId);

        // ── new Catalog ──
        StringBuilder cat = new StringBuilder("<<\n  /Type /Catalog\n");
        if (rd.get(root, "Version").isNull()) {
            Double v = null;
            try {
                v = Double.parseDouble(rd.version);
            } catch (NumberFormatException e) {
                // no header version
            }
            if (v != null && v < 1.5) cat.append("  /Version /1.5\n");
        }
        cat.append(inc.catalogCopy(Set.of("AcroForm")));
        cat.append("  /AcroForm <<");
        if (acro != null && acroObj instanceof PdfObj.Dict) {
            for (String key : acro.sortedKeys()) {
                if (key.equals("Fields") || key.equals("SigFlags")) continue;
                cat.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(acro.get(key)));
            }
        }
        cat.append(" /Fields [");
        if (acro != null) {
            PdfObj rf = acro.get("Fields");
            if (rf instanceof PdfObj.Ref) rf = rd.resolve(rf);
            if (rf instanceof PdfObj.Arr) for (PdfObj f : ((PdfObj.Arr) rf).items()) cat.append(inc.serialize(f)).append(' ');
        }
        cat.append(fieldId).append(" 0 R] /SigFlags 3 >>\n>>");
        inc.writeObject(catId, Text.latin1(cat.toString()));

        byte[] doc = inc.finish(catId);
        long a = (long) sigStart + contentsAt;
        long b = a + 2L * PLACEHOLDER_BYTES + 2;
        if (doc[(int) a] != '<' || doc[(int) (b - 1)] != '>') throw new PdfException("placeholder position mismatch");
        long[] br = {0, a, b, doc.length - b};
        String field = "[" + br[0] + " " + br[1] + " " + br[2] + " " + br[3] + "]";
        if (field.length() > BYTE_RANGE_WIDTH) throw new PdfException("ByteRange does not fit");
        byte[] fb = Text.latin1(field);
        System.arraycopy(fb, 0, doc, sigStart + brAt, fb.length);
        MessageDigest h = Cms.md("SHA-256");
        h.update(doc, 0, (int) a);
        h.update(doc, (int) b, doc.length - (int) b);
        return new Prepared(doc, br, h.digest(), fieldName, placement);
    }

    /** CMS → hex into the placeholder (other bytes untouched); never truncates. */
    static byte[] embedCms(byte[] prepared, long[] br, byte[] cms) {
        if (cms.length == 0) throw new IllegalArgumentException("CMS empty");
        if (cms.length > PLACEHOLDER_BYTES) throw new PlaceholderOverflow(cms.length + " > " + PLACEHOLDER_BYTES + " bytes");
        int a = (int) br[1];
        int b = (int) br[2];
        if (br[0] != 0L || a <= 0 || b != a + 2L * PLACEHOLDER_BYTES + 2 || b + br[3] != prepared.length || prepared[a] != '<'
            || prepared[b - 1] != '>') {
            throw new IllegalArgumentException("ByteRange does not match the prepared document");
        }
        for (int i = a + 1; i < b - 1; i++) if (prepared[i] != '0') throw new IllegalArgumentException("placeholder already filled");
        byte[] out = prepared.clone();
        byte[] hex = Text.latin1(Text.hex(cms));
        System.arraycopy(hex, 0, out, a + 1, hex.length);
        return out;
    }

    /** /Contents value as viewers read it: hex-decoded, including the placeholder's zero padding (VRI key). */
    static byte[] signatureContents(byte[] signed, long[] br) {
        int a = (int) br[1];
        int b = (int) br[2];
        if (br[0] != 0L || a <= 0 || b <= a + 2 || b > signed.length || signed[a] != '<' || signed[b - 1] != '>') {
            throw new IllegalArgumentException("ByteRange does not point at /Contents");
        }
        byte[] v = Text.unhex(signed, a + 1, b - 1);
        if (v == null) throw new IllegalArgumentException("/Contents hex");
        return v;
    }

    private static void addWidgetToPage(Incremental inc, PdfDict page, PdfRef pageRef, int widget) {
        PdfReader rd = inc.reader;
        PdfObj annotsRaw = page.get("Annots");
        PdfObj annots = rd.resolve(annotsRaw);
        if (!annots.isNull() && !(annots instanceof PdfObj.Arr)) throw new PdfException("page /Annots is not an array");
        StringBuilder arr = new StringBuilder("[");
        if (annots instanceof PdfObj.Arr) for (PdfObj e : ((PdfObj.Arr) annots).items()) arr.append(inc.serialize(e)).append(' ');
        arr.append(widget).append(" 0 R]");
        PdfRef annotsRef = annotsRaw.ref();
        if (!annots.isNull() && annotsRef != null) {
            inc.writeObject(annotsRef.id(), Text.latin1(arr.toString()), annotsRef.gen());
            return;
        }
        StringBuilder b = new StringBuilder("<<");
        for (String key : page.sortedKeys()) {
            if (key.equals("Annots")) continue;
            b.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(page.get(key)));
        }
        b.append(" /Annots ").append(arr).append(" >>");
        inc.writeObject(pageRef.id(), Text.latin1(b.toString()), pageRef.gen());
    }

    /** First /Page of the /Pages tree (digitorus findFirstPage; bounded depth) + the reference it was reached by. */
    private static Object[] firstPage(PdfReader rd, PdfObj v, PdfRef owner, int depth) {
        if (depth > 32) return null;
        PdfRef ref = v.ref() != null ? v.ref() : owner;
        if (ref == null) return null;
        PdfDict d = rd.resolve(v).dict();
        if (d == null) return null;
        String t = rd.get(d, "Type").name();
        if ("Page".equals(t)) return new Object[] {d, ref};
        if ("Pages".equals(t)) {
            PdfObj kids = rd.get(d, "Kids");
            if (!(kids instanceof PdfObj.Arr)) return null;
            for (PdfObj kid : ((PdfObj.Arr) kids).items()) {
                Object[] p = firstPage(rd, kid, ref, depth + 1);
                if (p != null) return p;
            }
        }
        return null;
    }

    /** PDF text string → String (UTF-16BE with BOM, else PDFDocEncoding ≈ Latin-1) — digitorus `Text()`. */
    static String text(PdfObj o) {
        if (!(o instanceof PdfObj.Str)) return "";
        byte[] b = ((PdfObj.Str) o).bytes();
        if (b.length >= 2 && b[0] == (byte) 0xFE && b[1] == (byte) 0xFF) return new String(b, 2, b.length - 2, StandardCharsets.UTF_16BE);
        return new String(b, StandardCharsets.ISO_8859_1);
    }

    /** "(D:YYYYMMDDHHmmSS+08'00')" — always +08:00 (Go reference normalises to FixedZone +08). */
    static String pdfDate(Date t) {
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("GMT+08:00"), Locale.ROOT);
        c.setTime(t);
        return String.format(Locale.ROOT, "(D:%04d%02d%02d%02d%02d%02d+08'00')", c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1,
            c.get(Calendar.DAY_OF_MONTH), c.get(Calendar.HOUR_OF_DAY), c.get(Calendar.MINUTE), c.get(Calendar.SECOND));
    }

    /**
     * Go sigText: hex PDF text string — ASCII as is, else BOM + UTF-16BE. Null (not written) when empty after TrimSpace,
     * longer than [maxUnits] UTF-16 units, containing control chars or PDF keywords.
     */
    static String sigText(String input, int maxUnits) {
        String s = Text.trimSpace(input);
        if (s.isEmpty() || s.length() > maxUnits) return null;
        boolean ascii = true;
        for (int i = 0; i < s.length(); ) {
            int r = s.codePointAt(i);
            if (r < 0x20 || r == 0x7f || Character.getType(r) == Character.CONTROL) return null;
            if (r >= 0xD800 && r <= 0xDFFF) return null; // lone surrogate (Go: invalid UTF-8)
            if (r > 0x7e) ascii = false;
            i += Character.charCount(r);
        }
        for (String kw : KEYWORDS) if (s.contains(kw)) return null;
        if (ascii) return Text.hexString(Text.latin1(s));
        return Text.hexString(Der.concat(new byte[] {(byte) 0xfe, (byte) 0xff}, s.getBytes(StandardCharsets.UTF_16BE)));
    }
}
