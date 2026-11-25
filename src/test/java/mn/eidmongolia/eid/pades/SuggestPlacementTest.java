package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.junit.Test;

/**
 * PLACEMENT_SPEC.md §6b checks suggestPlacement shares with prepare (Go TestSuggestPlacementErrors), §1a default stamp
 * page (Go TestDefaultStampPage), and the default HTTP transport's total deadline.
 */
public class SuggestPlacementTest {
    private static final String DOC_A = "f5a6b7c8-d9e0-4f1a-8b2c-3d4e5f607182";

    @Test
    public void errors() {
        byte[] table = Golden.file("input/table-bottom.pdf");
        byte[] enc = Golden.file("input/encrypted.pdf");
        SignatureAppearance a = new SignatureAppearance(340, 36, 220, 64);
        Object[][] cases = {
            {"not-pdf", Golden.ascii("hello"), a, "PDF_INVALID"},
            {"encrypted", enc, a, "PDF_ENCRYPTED"},
            {"page-beyond", table, a.withPage(2), "REQUEST_INVALID"},
            {"outside", table, new SignatureAppearance(400, 36, 220, 64).withExact(true), "REQUEST_INVALID"},
            {"outside-auto", table, new SignatureAppearance(400, 36, 220, 64), "REQUEST_INVALID"},
            {"negative", table, new SignatureAppearance(-1, 36, 220, 64), "REQUEST_INVALID"},
            {"zero-size", table, new SignatureAppearance(1, 36, 0, 64), "REQUEST_INVALID"},
        };
        for (Object[] c : cases) {
            assertEquals((String) c[0], c[3], ErrorTest.code(() -> EidPades.suggestPlacement((byte[]) c[1], (SignatureAppearance) c[2])));
        }
        PlacementSuggestion s = EidPades.suggestPlacement(table, a.withExact(true));
        assertEquals(PlacementStatus.OVERLAP, s.status());
        assertEquals(340.0, s.x(), 0);
        assertEquals(36.0, s.y(), 0);
        assertEquals(1, s.pageCount());
        assertEquals(1, s.pages().size());
        // Without exact the same request moves off the table (golden table-bottom-visible).
        assertEquals(PlacementStatus.MOVED, EidPades.suggestPlacement(table, a).status());
    }

    private static void check(byte[] doc, String docId, int page, int n, String name) {
        assertArrayEquals(name, new int[] {page, n}, Appearance.defaultStampPage(doc, Precheck.VERIFY_URL + docId));
    }

    @Test
    public void defaultStampPage() {
        check(Golden.file("input/two-verify.pdf"), DOC_A, 1, 3, "two verify pages");
        check(Golden.file("input/two-verify.pdf"), "a6b7c8d9-e0f1-4a2b-9c3d-4e5f60718293", 3, 3, "other docId");
        check(Golden.file("input/fake-verify.pdf"), DOC_A, 2, 2, "fake verify");
        check(Golden.file("input/quartz-pdf13.pdf"), DOC_A, 1, 1, "no verify page");
    }

    /** Hand-built pages: a direct /Link annotation, every page a verify page → the last page. */
    @Test
    public void allVerifyPages() {
        String uri = Precheck.VERIFY_URL + DOC_A;
        String[] objs = {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [<< /Subtype /Link /A << /S /URI /URI (" + uri + ") >> >>] >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [5 0 R] >>",
            "<< /Type /Annot /Subtype /Link /Rect [0 0 1 1] /A << /S /URI /URI (" + uri + ") >> >>",
        };
        StringBuilder b = new StringBuilder("%PDF-1.4\n");
        int[] offs = new int[objs.length];
        for (int i = 0; i < objs.length; i++) {
            offs[i] = b.length();
            b.append(i + 1).append(" 0 obj\n").append(objs[i]).append("\nendobj\n");
        }
        int x = b.length();
        b.append("xref\n0 ").append(objs.length + 1).append("\n0000000000 65535 f \n");
        for (int o : offs) b.append(String.format(Locale.ROOT, "%010d 00000 n \n", o));
        b.append("trailer\n<< /Size ").append(objs.length + 1).append(" /Root 1 0 R >>\nstartxref\n").append(x).append("\n%%EOF\n");
        check(b.toString().getBytes(StandardCharsets.US_ASCII), DOC_A, 2, 2, "all verify");
    }

    /** Serves one connection: headers, then [body] one byte every [gapMs]. */
    private static ServerSocket trickle(byte[] body, long gapMs) throws IOException {
        ServerSocket ss = new ServerSocket(0);
        Thread t = new Thread(() -> {
            try (Socket s = ss.accept()) {
                InputStream in = s.getInputStream();
                int state = 0; // read until CRLF CRLF
                while (state < 4) {
                    int c = in.read();
                    if (c < 0) break;
                    state = (c == '\r' && (state == 0 || state == 2)) || (c == '\n' && (state == 1 || state == 3)) ? state + 1 : 0;
                }
                OutputStream out = s.getOutputStream();
                out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                out.flush();
                for (byte x : body) {
                    Thread.sleep(gapMs);
                    out.write(x);
                    out.flush();
                }
            } catch (Exception e) {
                // client gave up
            }
        });
        t.setDaemon(true);
        t.start();
        return ss;
    }

    /** DefaultHttp: the timeout is a total deadline (Go `http.Client.Timeout`), not a per-read idle timeout. */
    @Test
    public void tricklingServerHitsTotalDeadline() throws Exception {
        byte[] body = new byte[20];
        java.util.Arrays.fill(body, (byte) 'x');
        try (ServerSocket ss = trickle(body, 200)) {
            long t0 = System.nanoTime();
            try {
                DefaultHttp.send("GET", "http://127.0.0.1:" + ss.getLocalPort() + "/", null, null, 1_000);
                throw new AssertionError("expected a timeout");
            } catch (SocketTimeoutException e) {
                // expected
            }
            long ms = (System.nanoTime() - t0) / 1_000_000;
            assertTrue("took " + ms + " ms", ms >= 900 && ms <= 3_000);
        }
    }

    @Test
    public void fastServerWithinDeadline() throws Exception {
        byte[] body = "ok".getBytes(StandardCharsets.US_ASCII);
        try (ServerSocket ss = trickle(body, 1)) {
            assertArrayEquals(body, DefaultHttp.send("GET", "http://127.0.0.1:" + ss.getLocalPort() + "/", null, null, 5_000));
        }
    }
}
