package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.zip.Deflater;
import org.junit.Test;

/**
 * The structure pre-check limits of corpus v14 (Go nesting.go CheckStructure / TS checkStructure), at and just past each
 * bound: xref sections, xref-stream /W and /Index, total xref-stream rows, xref-stream filters and the shared inflate
 * budget, and the object-stream lookup work budget. The corpus has one case per rule; these pin the boundaries.
 */
public class StructureLimitsTest {
    private static final long BOUND_MS = 5_000;

    private static byte[] latin1(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void ok(String what, byte[] doc) {
        long t0 = System.nanoTime();
        try {
            Structure.check(doc);
        } catch (Structure.Failure e) {
            fail(what + ": rejected");
        }
        assertTrue(what, (System.nanoTime() - t0) / 1_000_000 < BOUND_MS);
    }

    private static void rejected(String what, byte[] doc) {
        long t0 = System.nanoTime();
        try {
            Structure.check(doc);
            fail(what + ": accepted");
        } catch (Structure.Failure e) {
            assertTrue(what, (System.nanoTime() - t0) / 1_000_000 < BOUND_MS);
        }
    }

    private static byte[] trailers(int n, String extra) {
        StringBuilder b = new StringBuilder("%PDF-1.7\n").append(extra);
        for (int i = 0; i < n; i++) b.append("trailer\n<< /Size 1 >>\n");
        return latin1(b.append("%%EOF\n").toString());
    }

    /** One xref stream object per dictionary (stream data = [data]). */
    private static byte[] xrefStreams(byte[] data, String... dicts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(latin1("%PDF-1.7\n"));
        int n = 1;
        for (String d : dicts) {
            o.writeBytes(latin1(n++ + " 0 obj\n<< /Type /XRef " + d + " /Length " + data.length + " >>\nstream\n"));
            o.writeBytes(data);
            o.writeBytes(latin1("\nendstream\nendobj\n"));
        }
        o.writeBytes(latin1("%%EOF\n"));
        return o.toByteArray();
    }

    private static byte[] xref(String... dicts) {
        return xrefStreams(new byte[0], dicts);
    }

    private static byte[] deflate(byte[] b) {
        Deflater d = new Deflater(9);
        d.setInput(b);
        d.finish();
        ByteArrayOutputStream z = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        while (!d.finished()) z.write(buf, 0, d.deflate(buf));
        d.end();
        return z.toByteArray();
    }

    @Test
    public void xrefSections() {
        ok("128 trailers", trailers(128, ""));
        rejected("129 trailers", trailers(129, ""));
        rejected("128 trailers + an xref stream", trailers(128, "9 0 obj\n<< /Type /XRef /Size 1 /W [1 1 1] >>\nendobj\n"));
        ok("a /Type /XRef trailer dictionary counts once", trailers(127, "trailer\n<< /Type /XRef /Size 1 >>\n"));
        rejected("... and is still a section", trailers(128, "trailer\n<< /Type /XRef /Size 1 >>\n"));
    }

    @Test
    public void xrefStreamW() {
        ok("W [1 2 1]", xref("/Size 3 /W [1 2 1]"));
        ok("W [8 8 8]", xref("/Size 3 /W [8 8 8]"));
        rejected("W entry 9", xref("/Size 3 /W [1 9 1]"));
        rejected("W entry negative", xref("/Size 3 /W [1 -1 1]"));
        rejected("row width 0", xref("/Size 3 /W [0 0 0]"));
        ok("short W — left to the reader", xref("/Size 3 /W [0 0]"));
        ok("non-integer W — left to the reader", xref("/Size 3 /W [0 /x 0]"));
        ok("W by reference — left to the reader", xref("/Size 3 /W 5 0 R"));
    }

    @Test
    public void xrefStreamIndex() {
        ok("start + count = 2^21", xref("/W [1 2 1] /Index [0 2097152]"));
        rejected("start + count > 2^21", xref("/W [1 2 1] /Index [1 2097152]"));
        rejected("negative start", xref("/W [1 2 1] /Index [-1 5]"));
        rejected("negative count", xref("/W [1 2 1] /Index [0 -5]"));
        rejected("huge count with zero width", xref("/W [0 0 0] /Index [0 1000000000]"));
        ok("odd Index — left to the reader", xref("/W [1 2 1] /Index [0 5 7]"));
        ok("two streams, 2^21 rows together", xref("/W [1 2 1] /Index [0 1048576]", "/W [1 2 1] /Index [0 1048576]"));
        rejected("two streams, 2^21 + 1 rows", xref("/W [1 2 1] /Index [0 1048576]", "/W [1 2 1] /Index [0 1048577]"));
        ok("/Size without /Index counts", xref("/W [1 2 1] /Size 2097152"));
        rejected("/Size of two streams counts", xref("/W [1 2 1] /Size 1500000", "/W [1 2 1] /Size 1500000"));
    }

    @Test
    public void xrefStreamFilters() {
        byte[] small = deflate(new byte[16]);
        ok("FlateDecode", xrefStreams(small, "/Size 4 /W [1 2 1] /Filter /FlateDecode"));
        rejected("two filters", xrefStreams(small, "/Size 4 /W [1 2 1] /Filter [/FlateDecode /FlateDecode]"));
        byte[] big = deflate(new byte[(32 << 20) + 1]);
        rejected("inflated over 32 MiB", xrefStreams(big, "/Size 4 /W [1 2 1] /Filter /FlateDecode"));
        byte[] half = deflate(new byte[17 << 20]);
        rejected("budget shared by two xref streams",
            xrefStreams(half, "/Size 4 /W [1 2 1] /Filter /FlateDecode", "/Size 4 /W [1 2 1] /Filter /FlateDecode"));
    }

    /** An unfiltered object stream with [pairs] header pairs (all at offset 0) followed by [pad] bytes of data. */
    private static byte[] objStm(int pairs, int pad, String length) {
        StringBuilder h = new StringBuilder();
        for (int i = 0; i < pairs; i++) h.append(i + 2).append(" 0 ");
        String data = h + "1 " + " ".repeat(pad);
        return latin1("%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N " + pairs + " /First " + h.length() + length + " >>\nstream\n" + data
            + "\nendstream\nendobj\n%%EOF\n");
    }

    @Test
    public void objectStreamWorkBudget() {
        // 1100 pairs × ~1 MiB > 2^30; with a direct /Length of 1000 the charge is 1100 × 1000
        rejected("pairs × data length > 1 GiB", objStm(1100, 1 << 20, ""));
        ok("direct /Length bounds the charge", objStm(1100, 1 << 20, " /Length 1000"));
        ok("under the budget", objStm(900, 1 << 20, ""));
    }
}
