package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import mn.eidmongolia.eid.internal.Der;
import org.junit.Test;

/**
 * PLACEMENT_SPEC.md conformance: the occupancy scanner and candidate search against the Go reference vectors
 * (golden/placement/vectors.json, box-for-box), plus robustness on malformed content / broken streams.
 */
public class PlacementTest {
    private static final class Run {
        final long[] box;
        final int rot;
        final List<long[]> boxes;
        final StampPlacement.Result result;

        Run(long[] box, int rot, List<long[]> boxes, StampPlacement.Result result) {
            this.box = box;
            this.rot = rot;
            this.boxes = boxes;
            this.result = result;
        }
    }

    /** Scanner + choice exactly as SignatureRevision.prepare runs them. */
    private static Run run(byte[] doc, int page, double[] q) {
        Incremental inc = new Incremental(doc);
        PdfReader rd = inc.reader;
        Object[] p = Appearance.nthPage(rd, inc.root().get("Pages"), inc.rootRef(), page);
        if (p == null) throw new IllegalStateException("page " + page);
        PdfDict pd = (PdfDict) p[0];
        int id = ((PdfRef) p[1]).id();
        Appearance.Geometry g = Appearance.geometry(rd, pd);
        long x = Appearance.round100(q[0]);
        long y = Appearance.round100(q[1]);
        long w = Appearance.round100(q[2]);
        long h = Appearance.round100(q[3]);
        List<long[]> boxes;
        try {
            boxes = Occupancy.scan(rd, pd, id, g.box);
        } catch (Exception e) {
            boxes = null;
        }
        return new Run(g.box, g.rot, boxes, StampPlacement.choose(rd, pd, id, g.box, g.rot, x, y, w, h, false));
    }

    private static List<Long> longs(Object a) {
        List<Long> out = new ArrayList<>();
        for (Object o : (List<?>) a) out.add(((Json.Num) o).longValue());
        return out;
    }

    private static List<Long> boxed(long[] a) {
        List<Long> out = new ArrayList<>();
        for (long v : a) out.add(v);
        return out;
    }

    @Test
    public void vectors() {
        List<?> vs = (List<?>) Json.parse(Golden.file("placement/vectors.json"));
        assertEquals(29, vs.size());
        for (Object o : vs) {
            Json.Obj v = (Json.Obj) o;
            String name = v.getString("name");
            Json.Obj e = v.getObj("expect");
            List<Object> req = v.getArr("request");
            double[] q = new double[4];
            for (int i = 0; i < 4; i++) q[i] = ((Json.Num) req.get(i)).doubleValue();
            Run got = run(Golden.file(v.getString("input")), v.getInt("page"), q);
            assertEquals(name + " box", longs(e.getArr("box")), boxed(got.box));
            assertEquals(name + " rotate", e.getInt("rotate"), got.rot);
            List<Object> wb = e.optArr("boxes");
            List<List<Long>> want = null;
            if (wb != null) {
                want = new ArrayList<>();
                for (Object b : wb) want.add(longs(b));
            }
            List<List<Long>> have = null;
            if (got.boxes != null) {
                have = new ArrayList<>();
                for (long[] b : got.boxes) have.add(boxed(b));
            }
            assertEquals(name + " boxes", want, have);
            assertEquals(name + " status", e.getString("status"), got.result.status.wire);
            assertEquals(name + " position", Arrays.asList(e.getLong("x"), e.getLong("y")), Arrays.asList(got.result.x, got.result.y));
        }
    }

    /** Go TestPlacementCandidates: the trial order on A4 with the portal's default request. */
    @Test
    public void candidates() {
        List<long[]> c = StampPlacement.candidates(59528, 84189, 34000, 3600, 22000, 6400);
        assertEquals(Arrays.asList(34000L, 3600L), boxed(c.get(0)));
        assertEquals(Arrays.asList(3528L, 3600L), boxed(c.get(1)));
        assertEquals(Arrays.asList(34000L, 4800L), boxed(c.get(2)));
        int n = (84189 - 3600 - 3600 - 6400) / 1200;
        assertEquals(2 + 2 * n, c.size());
        assertEquals(Arrays.asList(3528L, 4800L), boxed(c.get(2 + n)));
        List<long[]> centred = StampPlacement.candidates(1000, 3000, 400, 0, 200, 100);
        assertEquals(3, centred.size());
        assertEquals(Arrays.asList(400L, 1200L), boxed(centred.get(1)));
    }

    // ── Robustness ──

    private static byte[] s(String x) {
        return x.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Go placement_test fxPDF: a minimal classic-xref PDF, objs[0] = object 1 (Catalog). */
    private static byte[] pdf(List<byte[]> objs) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(s("%PDF-1.4\n%âãÏÓ\n"));
        List<Integer> offs = new ArrayList<>();
        for (int i = 0; i < objs.size(); i++) {
            offs.add(b.size());
            b.writeBytes(s((i + 1) + " 0 obj\n"));
            b.writeBytes(objs.get(i));
            b.writeBytes(s("\nendobj\n"));
        }
        int x = b.size();
        b.writeBytes(s("xref\n0 " + (objs.size() + 1) + "\n0000000000 65535 f \n"));
        for (int o : offs) b.writeBytes(s(String.format(Locale.ROOT, "%010d 00000 n \n", o)));
        b.writeBytes(s("trailer\n<< /Size " + (objs.size() + 1) + " /Root 1 0 R >>\nstartxref\n" + x + "\n%%EOF\n"));
        return b.toByteArray();
    }

    private static byte[] stream(String dict, byte[] data) {
        return Der.concat(s("<< " + dict + "/Length " + data.length + " >>\nstream\n"), data, s("\nendstream"));
    }

    /** One letter page whose content is [content] (+ a self-recursive form /X). */
    private static byte[] page(byte[] content, String filter) {
        return pdf(Arrays.asList(
            s("<< /Type /Catalog /Pages 2 0 R >>"),
            s("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"),
            s("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> /XObject << /X 6 0 R >> >> /Contents 4 0 R >>"),
            stream(filter, content),
            s("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 32 /Widths [250 300] >>"),
            stream("/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Resources << /XObject << /X 6 0 R >> >> ", content)));
    }

    private static byte[] page(byte[] content) {
        return page(content, "");
    }

    private static StampPlacement.Status status(byte[] doc) {
        return run(doc, 1, new double[] {340, 36, 220, 64}).result.status;
    }

    /** Go compress/zlib BestCompression of "0 g 340 36 220 64 re f" (fills the requested spot). */
    private static final byte[] ZLIB = bytes(
        0x78, 0xda, 0x32, 0x50, 0x48, 0x57, 0x30, 0x36, 0x31, 0x50, 0x30, 0x36, 0x53, 0x30, 0x32, 0x32,
        0x50, 0x30, 0x33, 0x51, 0x28, 0x4a, 0x55, 0x48, 0x03, 0x04, 0x00, 0x00, 0xff, 0xff, 0x31, 0xed, 0x04, 0xb3);

    private static byte[] bytes(int... v) {
        byte[] out = new byte[v.length];
        for (int i = 0; i < v.length; i++) out[i] = (byte) v[i];
        return out;
    }

    /** zlib framing (RFC 1950): header, truncation and Adler-32 errors make the page unscannable, never a crash. */
    @Test
    public void brokenFlate() {
        assertEquals("0 g 340 36 220 64 re f", new String(Occupancy.inflate(ZLIB, 1 << 20), StandardCharsets.ISO_8859_1));
        String flate = "/Filter /FlateDecode ";
        assertEquals(StampPlacement.Status.MOVED, status(page(ZLIB, flate)));
        byte[] badAdler = ZLIB.clone();
        badAdler[badAdler.length - 1] ^= 1;
        byte[] badHeader = ZLIB.clone();
        badHeader[1] ^= 1;
        // FDICT (0x78 0x20, FCHECK valid): Go accepts DICTID 1 (Adler-32 of no dictionary), rejects any other.
        byte[] body = Arrays.copyOfRange(ZLIB, 2, ZLIB.length);
        byte[] dict1 = Der.concat(bytes(0x78, 0x20, 0, 0, 0, 1), body);
        byte[] dict2 = Der.concat(bytes(0x78, 0x20, 0, 0, 0, 2), body);
        byte[] truncated = Arrays.copyOf(ZLIB, ZLIB.length - 3); // Adler-32 cut
        byte[] truncatedData = Arrays.copyOf(ZLIB, ZLIB.length - 8); // deflate data cut
        byte[] trailing = Der.concat(ZLIB, s(" AB")); // bytes after the checksum are ignored
        Object[][] cases = {
            {"adler", badAdler, StampPlacement.Status.UNSCANNED},
            {"header", badHeader, StampPlacement.Status.UNSCANNED},
            {"fdict-1", dict1, StampPlacement.Status.MOVED},
            {"fdict-2", dict2, StampPlacement.Status.UNSCANNED},
            {"truncated", truncated, StampPlacement.Status.UNSCANNED},
            {"truncated-data", truncatedData, StampPlacement.Status.UNSCANNED},
            {"empty", new byte[0], StampPlacement.Status.UNSCANNED},
            {"trailing", trailing, StampPlacement.Status.MOVED},
        };
        for (Object[] c : cases) assertEquals((String) c[0], c[2], status(page((byte[]) c[1], flate)));
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(ZLIB, "/Filter /FlateDecode /DecodeParms << /Predictor 12 >> ")));
        assertEquals(StampPlacement.Status.MOVED, status(page(ZLIB, "/Filter [/FlateDecode] /DecodeParms [null] ")));
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(ZLIB, "/Filter [/FlateDecode /FlateDecode] ")));
        try {
            Occupancy.inflate(ZLIB, 10);
            fail("output over the limit");
        } catch (Occupancy.Unscannable e) {
            // expected
        }
    }

    /**
     * Arbitrary content bytes (Go FuzzOccupancy): the scanner never throws past its boundary, loops or escapes its limits;
     * it either returns boxes or reports unscannable. Deterministic PRNG (same xorshift as iOS/Android).
     */
    @Test
    public void arbitraryContent() {
        long[] seed = {0x9E3779B97F4A7C15L};
        java.util.function.LongSupplier next = () -> {
            long x = seed[0];
            x ^= x << 13;
            x ^= x >>> 7;
            x ^= x << 17;
            seed[0] = x;
            return x;
        };
        java.util.function.IntUnaryOperator rnd = n -> (int) Long.remainderUnsigned(next.getAsLong(), n);
        byte[] alphabet = s("0123456789.-+ \n\r\t()<>[]{}/%#\\qQcmwgGrRkKsSfFbBnWhlvyreTcTwTzTLTfTdTDTmTjTJ'\"*DoBIIDEIBTETshcsCS");
        List<byte[]> docs = new ArrayList<>(Arrays.asList(
            s("BT /F1 12 Tf (abc) Tj ET q 1 0 0 1 0 0 cm 0 0 10 10 re f Q BI /W 1 ID x EI"),
            s("q 1e308 0 0 1e308 0 0 cm 1 w 0 0 m 99999999999999999999999999999 1 l S Q"),
            s("BT /F1 99999999999999999999999999999 Tf 99999999999999999999999999999 Tz (aaaa) Tj ET"),
            s("/X Do"),
            s("[".repeat(40)),
            s("q ".repeat(70)),
            s("BI /W 1 ID"),
            s("(unterminated \\"),
            s("<abc")));
        for (int k = 0; k < 300; k++) {
            byte[] d = new byte[rnd.applyAsInt(400)];
            for (int i = 0; i < d.length; i++) d[i] = alphabet[rnd.applyAsInt(alphabet.length)];
            docs.add(d);
        }
        for (int k = 0; k < 100; k++) {
            byte[] d = new byte[rnd.applyAsInt(300)];
            for (int i = 0; i < d.length; i++) d[i] = (byte) next.getAsLong();
            docs.add(d);
        }
        for (byte[] content : docs) {
            Run got = run(page(content), 1, new double[] {340, 36, 220, 64});
            if (got.result.status == StampPlacement.Status.UNSCANNED) assertNull(got.boxes);
            else assertNotNull(got.boxes);
        }
        // The self-recursive form hits the depth limit, never recursion without end.
        assertEquals(StampPlacement.Status.UNSCANNED, status(page(s("/X Do"))));
        assertTrue(docs.size() > 400);
    }
}
