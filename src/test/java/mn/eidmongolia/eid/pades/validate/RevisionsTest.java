package mn.eidmongolia.eid.pades.validate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PName;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PReal;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PRef;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PStr;
import mn.eidmongolia.eid.pades.validate.PdfObjects.PdfBudget;
import org.junit.Test;

public class RevisionsTest {
    private static final PadesSupport NO_SUPPORT = new PadesSupport() {
        @Override
        public boolean structureOk(byte[] doc) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<byte[]> appearanceObjects(int w, int h, int rotate, String name, String role, String lang, String date,
            String url, boolean seal, int[] ids) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] visibleWidget(String fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId) {
            throw new UnsupportedOperationException();
        }
    };

    private static byte[] b(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static Object parse(String s) {
        return new PdfParser(b(s), s.length(), 0, new PdfBudget()).value(0);
    }

    private static void assertRejected(String s) {
        try {
            parse(s);
            fail("expected PdfObjError for " + s);
        } catch (PdfObjError expected) {
            // ok
        }
    }

    // ── parser ──

    @Test
    public void parsesValues() {
        assertEquals(42L, parse("42"));
        assertEquals(-7L, parse("-7"));
        assertEquals(1.5, ((PReal) parse("1.5")).v, 0);
        PRef r = (PRef) parse("12 0 R");
        assertEquals(12, r.num);
        assertEquals("A B", ((PName) parse("/A#20B")).v);
        assertEquals("a\n(b)ÿ", ((PStr) parse("(a\\n\\(b\\)\\377)")).v);
        assertEquals("«À", ((PStr) parse("<AB C>")).v);
        Map<String, Object> d = PdfObjects.dict(parse("<</A 1 /B null /C [1 2.0 /x]>>"));
        assertEquals(Arrays.asList("A", "C"), List.copyOf(d.keySet()));
    }

    @Test
    public void rejectsMalformedAndOverLimit() {
        assertRejected("<</A 1 /A 2>>");
        assertRejected("1.2.3");
        assertRejected("99999999999999999999");
        assertRejected("8388608 0 R");
        assertRejected("1 65536 R");
        assertRejected("(unterminated");
        assertRejected("<0G>");
        assertRejected("/A#4");
        assertRejected("[1 2");
        assertRejected("bogus");
        assertRejected("[".repeat(70) + "]".repeat(70));
        assertEquals(1L, PdfObjects.dict(parse("<</A 1 /A 1>>")).get("A"));
    }

    @Test
    public void nodeBudgetIsEnforced() {
        PdfBudget budget = new PdfBudget();
        budget.nodes = 3;
        try {
            new PdfParser(b("[1 2 3 4]"), 9, 0, budget).value(0);
            fail();
        } catch (PdfObjError expected) {
            // ok
        }
    }

    @Test
    public void pdfEqualIsTyped() {
        assertFalse(PdfObjects.pdfEqual(90L, new PReal(90)));
        assertTrue(PdfObjects.pdfEqual(new PReal(0.0), new PReal(-0.0)));
        assertTrue(PdfObjects.pdfEqual(parse("<</A [1 (x) /n 2 0 R]>>"), parse("<< /A [ 1 (x) /n 2 0 R ] >>")));
        assertFalse(PdfObjects.pdfEqual(parse("<</A 1>>"), parse("<</A 1 /B 2>>")));
        assertFalse(PdfObjects.pdfEqual(parse("[1]"), null));
        assertTrue(PdfObjects.pdfEqual(null, null));
    }

    // ── inflate ──

    private static byte[] zlib(byte[] data) {
        Deflater d = new Deflater();
        d.setInput(data);
        d.finish();
        byte[] buf = new byte[data.length + 64];
        int n = d.deflate(buf);
        d.end();
        return Arrays.copyOf(buf, n);
    }

    @Test
    public void zlibStrictSemantics() {
        byte[] data = b("hello hello hello hello");
        byte[] z = zlib(data);
        assertTrue(Arrays.equals(data, PdfObjects.zlibStrict(z, 1000)));
        byte[] badSum = z.clone();
        badSum[badSum.length - 1] ^= 1;
        expectError(() -> PdfObjects.zlibStrict(badSum, 1000));
        expectError(() -> PdfObjects.zlibStrict(Arrays.copyOf(z, z.length - 4), 1000)); // no adler32
        expectError(() -> PdfObjects.zlibStrict(Arrays.copyOf(z, z.length / 2), 1000)); // truncated
        expectError(() -> PdfObjects.zlibStrict(z, data.length - 1)); // over the budget
        byte[] badHeader = z.clone();
        badHeader[1] ^= 0x20;
        expectError(() -> PdfObjects.zlibStrict(badHeader, 1000));
        expectError(() -> PdfObjects.zlibStrict(new byte[] {0x78}, 1000));
    }

    private static void expectError(Runnable r) {
        try {
            r.run();
            fail("expected PdfObjError");
        } catch (PdfObjError expected) {
            // ok
        }
    }

    // ── classifier ──

    /** Builds a body with "n 0 obj ... endobj" objects, recording offsets. */
    private static final class Builder {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final Map<Integer, Integer> offs = new LinkedHashMap<>();

        Builder(byte[] prefix) {
            out.writeBytes(prefix);
        }

        void raw(String s) {
            out.writeBytes(b(s));
        }

        void obj(int num, String body) {
            offs.put(num, out.size());
            raw(num + " 0 obj\n" + body + "\nendobj\n");
        }

        /** xref table over the recorded objects (one subsection per object) + trailer + startxref. */
        byte[] finish(String trailer) {
            int xref = out.size();
            StringBuilder sb = new StringBuilder("xref\n");
            for (Map.Entry<Integer, Integer> e : offs.entrySet()) {
                sb.append(e.getKey()).append(" 1\n").append(String.format("%010d 00000 n\r\n", e.getValue()));
            }
            sb.append("trailer\n").append(trailer).append("\nstartxref\n").append(xref).append("\n%%EOF\n");
            raw(sb.toString());
            return out.toByteArray();
        }
    }

    private static byte[] basePdf() {
        Builder bd = new Builder(new byte[0]);
        bd.raw("%PDF-1.7\n");
        bd.obj(1, "<< /Type /Catalog /Pages 2 0 R >>");
        bd.obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>");
        bd.obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>");
        return bd.finish("<< /Size 4 /Root 1 0 R >>");
    }

    private static final long[] BYTE_RANGE = {0, 10, 20, 999_999};

    private static byte[] signedUpdate(byte[] base, boolean touchPage) {
        Builder up = new Builder(base);
        up.obj(1, "<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /SigFlags 3 >> >>");
        if (touchPage) up.obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>");
        up.obj(4, "<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signature 1) /V 5 0 R /Rect [0 0 0 0] /F 132 >>");
        up.obj(5, "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0 10 20 999999]"
            + " /Contents <00> >>");
        int prev = lastStartxref(base);
        return up.finish("<< /Size 6 /Root 1 0 R /Prev " + prev + " >>");
    }

    private static int lastStartxref(byte[] doc) {
        String s = new String(doc, StandardCharsets.ISO_8859_1);
        int i = s.lastIndexOf("startxref\n") + "startxref\n".length();
        return Integer.parseInt(s.substring(i, s.indexOf('\n', i)));
    }

    private static Revisions revisions(byte[] doc, String profile) {
        return new Revisions(doc, Map.of(5, BYTE_RANGE.clone()), profile, NO_SUPPORT);
    }

    @Test
    public void viewOpensBase() {
        byte[] base = basePdf();
        PdfView v = PdfView.open(base, base.length, new PdfBudget());
        assertEquals(1, v.sections.size());
        assertTrue(PdfObjects.isDict(v.get(3)));
        assertNull(v.deref(new PRef(9, 0)));
    }

    @Test
    public void signatureOnlyUpdateIsAccepted() {
        byte[] base = basePdf();
        byte[] doc = signedUpdate(base, false);
        LaterChanges lc = revisions(doc, "broad").later(base.length);
        assertTrue(lc.signaturesOnly);
        assertEquals(1, lc.signatures);
        assertFalse(lc.visible);
    }

    @Test
    public void contentChangeIsRejected() {
        byte[] base = basePdf();
        byte[] doc = signedUpdate(base, true);
        assertFalse(revisions(doc, "broad").later(base.length).signaturesOnly);
    }

    @Test
    public void unknownSignatureIsRejected() {
        byte[] base = basePdf();
        byte[] doc = signedUpdate(base, false);
        Revisions r = new Revisions(doc, Map.of(5, new long[] {0, 10, 20, 1}), "broad", NO_SUPPORT);
        assertFalse(r.later(base.length).signaturesOnly);
    }

    @Test
    public void hostileInputsNeverThrow() {
        byte[] base = basePdf();
        byte[] doc = signedUpdate(base, false);
        for (int cut = 0; cut < doc.length; cut += 7) {
            byte[] t = Arrays.copyOf(doc, cut);
            LaterChanges lc = revisions(t, "own").later(base.length);
            assertFalse(lc.signaturesOnly);
        }
        for (int i = base.length; i < doc.length; i += 3) {
            byte[] m = doc.clone();
            m[i] = (byte) (m[i] ^ 0x5a);
            revisions(m, "broad").later(base.length); // must not throw
        }
        assertFalse(revisions(doc, "broad").later(0).signaturesOnly);
        assertFalse(revisions(doc, "broad").later(doc.length).signaturesOnly);
        assertFalse(revisions(b("garbage"), "broad").later(3).signaturesOnly);
    }
}
