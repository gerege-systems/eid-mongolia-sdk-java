package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.TreeMap;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/** Hostile-PDF parser behaviour found in the 0.1.0 re-review (no golden vector covers these). */
public class ParserHardeningTest {
    /** Minimal PDF: objects (id → body bytes), classic xref table, trailer. */
    private static byte[] pdf(Map<Integer, byte[]> objects, String trailerExtra) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = "%PDF-1.7\n".getBytes(StandardCharsets.ISO_8859_1);
        out.write(head, 0, head.length);
        TreeMap<Integer, Integer> offsets = new TreeMap<>();
        for (Map.Entry<Integer, byte[]> e : new TreeMap<>(objects).entrySet()) {
            offsets.put(e.getKey(), out.size());
            byte[] b = Der.concat(Text.latin1(e.getKey() + " 0 obj\n"), e.getValue(), Text.latin1("\nendobj\n"));
            out.write(b, 0, b.length);
        }
        int xref = out.size();
        int size = offsets.lastKey() + 1;
        StringBuilder sb = new StringBuilder("xref\n0 " + size + "\n0000000000 65535 f\r\n");
        for (int id = 1; id < size; id++) {
            Integer o = offsets.get(id);
            sb.append(o == null ? "0000000000 65535 f\r\n" : String.format(java.util.Locale.ROOT, "%010d 00000 n\r\n", o));
        }
        sb.append("trailer\n<< /Size ").append(size).append(" /Root 1 0 R").append(trailerExtra).append(" >>\nstartxref\n")
            .append(xref).append("\n%%EOF\n");
        byte[] t = Text.latin1(sb.toString());
        out.write(t, 0, t.length);
        return out.toByteArray();
    }

    private static Map<Integer, byte[]> page(String contents) {
        Map<Integer, byte[]> o = new TreeMap<>();
        o.put(1, Text.latin1("<< /Type /Catalog /Pages 2 0 R >>"));
        o.put(2, Text.latin1("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"));
        o.put(3, Text.latin1("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R >>"));
        o.put(4, Text.latin1(contents));
        return o;
    }

    /**
     * A stream whose /Length refers to itself (or two streams to each other) recursed until StackOverflowError — an
     * Error past every catch, out of the public API. Now the /Length lookup fails and the stream is read up to endstream.
     */
    @Test
    public void selfReferencingLengthDoesNotRecurse() {
        String data = "0 0 m 10 10 l S";
        for (String len : new String[] {"4 0 R", "5 0 R"}) {
            Map<Integer, byte[]> o = page("<< /Length " + len + " >>\nstream\n" + data + "\nendstream");
            o.put(5, Text.latin1("<< /Length 4 0 R >>\nstream\nx\nendstream"));
            byte[] doc = pdf(o, "");
            PdfReader r = PdfReader.open(doc);
            PdfObj s = r.obj(new PdfRef(4, 0));
            assertTrue(len, s instanceof PdfObj.Stream);
            assertArrayEquals(len, Text.latin1(data), r.decodedStream(s));
            try {
                EidPades.suggestPlacement(doc, new SignatureAppearance(36, 36, 220, 64));
            } catch (EidPadesException e) {
                // a stable error code is fine; an Error is not
            } catch (StackOverflowError e) {
                fail(len + ": StackOverflowError");
            }
        }
    }

    /** `/Filter /FlateDecode /Filter null`: the last duplicate wins (Go map, Structure) — null removes the key. */
    @Test
    public void laterNullRemovesDuplicateKey() {
        PdfObj o = new PdfLexer(Text.latin1("<< /Filter /FlateDecode /A 1 /Filter null >>")).parseObject();
        PdfDict d = o.dict();
        assertTrue(d.get("Filter").isNull());
        assertFalse(d.map().containsKey("Filter"));
        assertEquals(Long.valueOf(1), d.get("A").asLong());
        PdfDict d2 = new PdfLexer(Text.latin1("<< /Filter null /Filter /FlateDecode >>")).parseObject().dict();
        assertEquals("FlateDecode", d2.get("Filter").name());
    }

    /** An xref stream /Index count beyond the /Size limit (2^21) adds no entries past it (hostile count → no allocation). */
    @Test
    public void xrefStreamIndexBeyondSizeLimitIgnored() {
        int rows = (1 << 21) + 4096;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] head = Text.latin1("%PDF-1.7\n");
        out.write(head, 0, head.length);
        int catOff = out.size();
        byte[] cat = Text.latin1("1 0 obj\n<< /Type /Catalog >>\nendobj\n");
        out.write(cat, 0, cat.length);
        int xrefOff = out.size();
        byte[] data = new byte[rows];
        Arrays.fill(data, (byte) 0x02); // type 2 rows, /W [1 0 0]
        byte[] x = Der.concat(Text.latin1("2 0 obj\n<< /Type /XRef /Size 3 /W [1 0 0] /Index [0 " + rows + "] /Root 1 0 R /Length "
            + rows + " >>\nstream\n"), data, Text.latin1("\nendstream\nendobj\nstartxref\n" + xrefOff + "\n%%EOF\n"));
        out.write(x, 0, x.length);
        assertTrue(catOff > 0);
        PdfReader r = PdfReader.open(out.toByteArray());
        assertTrue(String.valueOf(r.maxObjectId()), r.maxObjectId() < Structure.MAX_XREF_SIZE);
    }

    /** Go isVerifyPage reads /Annots under one recover(): an unreadable annotation → the page is not a verify page. */
    @Test
    public void unreadableAnnotationBeforeVerifyLink() {
        String uri = Precheck.VERIFY_URL + "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f";
        for (boolean broken : new boolean[] {false, true}) {
            Map<Integer, byte[]> o = page("<< /Length 0 >>\nstream\n\nendstream");
            o.put(3, Text.latin1("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Annots [5 0 R 6 0 R] >>"));
            o.put(5, Text.latin1(broken ? "<< /Subtype /Link /A 9 0 R >>" : "<< /Subtype /Square >>"));
            o.put(6, Text.latin1("<< /Subtype /Link /A << /S /URI /URI (" + uri + ") >> >>"));
            o.put(9, Text.latin1("<< /S /URI >>"));
            byte[] doc = pdf(o, "");
            if (broken) {
                // Point object 9's xref entry at garbage: resolving it throws.
                String s = new String(doc, StandardCharsets.ISO_8859_1);
                int at = s.indexOf("9 0 obj");
                int xref = s.lastIndexOf("xref\n0 ");
                int entry = s.indexOf("\n", s.indexOf("\n", xref) + 1) + 1 + 9 * 20; // row of object 9
                String bad = String.format(java.util.Locale.ROOT, "%010d", at + 2);
                doc = Text.latin1(s.substring(0, entry) + bad + s.substring(entry + 10));
            }
            PdfReader r = PdfReader.open(doc);
            PdfDict pg = r.obj(new PdfRef(3, 0)).dict();
            assertEquals(broken ? "broken" : "clean", !broken, Appearance.isVerifyPage(r, pg, uri));
        }
    }
}
