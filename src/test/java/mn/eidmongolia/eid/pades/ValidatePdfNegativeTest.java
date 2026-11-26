package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.pades.validate.PdfReport;
import mn.eidmongolia.eid.pades.validate.ValidatePdfException;
import mn.eidmongolia.eid.pades.validate.ValidatePdfOptions;
import org.junit.Test;

/**
 * Targeted negatives on top of the corpus: tampering inside the signed range, a shadow revision appended after the
 * signature, a foreign trust anchor, typed errors for malformed
 * input, and a deterministic mutation / truncation sweep (only a report or a ValidatePdfException, bounded time).
 */
public class ValidatePdfNegativeTest {
    private static final String VALID = "golden/output/quartz-pdf13.pdf";

    private static ValidatePdfOptions opts(String... roots) {
        List<byte[]> r = new ArrayList<>();
        for (String p : roots) r.add(Cert.pemSingle(ValidatePdfGoldenTest.res(p)));
        return ValidatePdfOptions.builder().roots(r)
            .issuers(List.of(Cert.pemSingle(ValidatePdfGoldenTest.res("golden/pki/04.pem"))))
            .time(Instant.parse("2026-10-14T04:00:30Z")).offline(true).build();
    }

    private static ValidatePdfOptions golden() {
        return opts("golden/pki/root.pem");
    }

    private static byte[] valid() {
        return ValidatePdfGoldenTest.res(VALID);
    }

    private static int indexOf(byte[] b, String s, int from) {
        byte[] k = s.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = from; i <= b.length - k.length; i++) {
            for (int j = 0; j < k.length; j++) if (b[i + j] != k[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static int lastIndexOf(byte[] b, String s) {
        byte[] k = s.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = b.length - k.length; i >= 0; i--) {
            for (int j = 0; j < k.length; j++) if (b[i + j] != k[j]) continue outer;
            return i;
        }
        return -1;
    }

    @Test
    public void control() {
        PdfReport r = EidPades.validatePdf(valid(), golden());
        assertEquals("valid", r.indication());
    }

    @Test
    public void byteFlippedInsideTheSignedRangeIsIntegrityFailed() {
        byte[] d = valid();
        int at = indexOf(d, "/Type /Catalog", 0) + 1; // first revision, inside ByteRange[0]
        d[at] = (byte) (d[at] ^ 0x20);
        PdfReport r = EidPades.validatePdf(d, golden());
        assertEquals("invalid", r.indication());
        assertEquals(List.of("integrity_failed"), r.signatures().get(0).problems());
    }

    @Test
    public void shadowRevisionAfterTheSignatureIsModifiedAfterSigning() {
        byte[] d = valid();
        String tail = new String(d, lastIndexOf(d, "trailer"), d.length - lastIndexOf(d, "trailer"), StandardCharsets.ISO_8859_1);
        int startxref = Integer.parseInt(tail.replaceAll("(?s).*startxref\\s+(\\d+).*", "$1"));
        int size = Integer.parseInt(tail.replaceAll("(?s).*/Size (\\d+).*", "$1"));
        String root = tail.replaceAll("(?s).*/Root (\\d+) 0 R.*", "$1");
        int o = lastIndexOf(d, "\n" + root + " 0 obj") + 1;
        int e = indexOf(d, "endobj", o);
        String body = new String(d, o, e - o, StandardCharsets.ISO_8859_1);
        int close = body.lastIndexOf(">>");
        String shadow = body.substring(0, close) + "/OpenAction << /S /JavaScript /JS (app.alert\\(1\\)) >> >>\n";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(d);
        int objAt = out.size();
        out.writeBytes((shadow + "endobj\n").getBytes(StandardCharsets.ISO_8859_1));
        int xrefAt = out.size();
        String x = "xref\n" + root + " 1\n" + String.format("%010d 00000 n \n", objAt) + "trailer\n<< /Size " + size + " /Root " + root
            + " 0 R /Prev " + startxref + " >>\nstartxref\n" + xrefAt + "\n%%EOF\n";
        out.writeBytes(x.getBytes(StandardCharsets.ISO_8859_1));
        PdfReport r = EidPades.validatePdf(out.toByteArray(), golden());
        PdfReport.SignatureReport s = r.signatures().get(0);
        assertTrue(s.problems().toString(), s.problems().contains("modified_after_signing"));
        assertNotEquals("valid", r.indication());
        assertEquals(false, s.extendedBySignaturesOnly());
    }

    @Test
    public void foreignTrustAnchorIsUntrusted() {
        PdfReport r = EidPades.validatePdf(valid(), opts("validate/pki/05.pem"));
        PdfReport.SignatureReport s = r.signatures().get(0);
        assertEquals("invalid", r.indication());
        assertTrue(s.problems().contains("untrusted_chain"));
        assertEquals(false, s.chainTrusted());
    }

    @Test
    public void embeddedNationalRootDoesNotTrustTheTestPki() {
        PdfReport r = EidPades.validatePdf(valid(), ValidatePdfOptions.builder().time(Instant.parse("2026-10-14T04:00:30Z")).offline(true).build());
        assertTrue(r.signatures().get(0).problems().contains("untrusted_chain"));
    }

    private static String code(byte[] d) {
        try {
            EidPades.validatePdf(d, golden());
            return "report";
        } catch (ValidatePdfException e) {
            return e.code();
        }
    }

    @Test
    public void malformedInputsAreTypedErrors() {
        assertEquals("PDF_INVALID", code(new byte[0]));
        assertEquals("PDF_INVALID", code("not a pdf".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("PDF_INVALID", code("%PDF-1.7\n%%EOF\n".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("PDF_INVALID", code("%PDF-1.7\nstartxref\n999999\n%%EOF\n".getBytes(StandardCharsets.US_ASCII)));
        byte[] deep = ("%PDF-1.7\n1 0 obj\n" + "[".repeat(5000) + "\nendobj\n%%EOF\n").getBytes(StandardCharsets.US_ASCII);
        assertEquals("PDF_INVALID", code(deep));
        assertEquals("PDF_TOO_LARGE", code(new byte[(10 << 20) + 1]));
    }

    @Test
    public void badOptionCertificateIsRequestInvalid() {
        try {
            EidPades.validatePdf(valid(), ValidatePdfOptions.builder().roots(List.of(new byte[] {0x30, 0x00})).offline(true).build());
            fail();
        } catch (ValidatePdfException e) {
            assertEquals("REQUEST_INVALID", e.code());
        }
    }

    /** Every truncation point (step) and deterministic mutations: a report or a typed error, each within a time bound. */
    @Test
    public void truncationAndMutationSweep() {
        List<byte[]> seeds = List.of(valid(), ValidatePdfGoldenTest.res("golden/output/quartz-objstm.pdf"),
            ValidatePdfGoldenTest.res("validate/input/deep-nesting-objstm.pdf"), ValidatePdfGoldenTest.res("validate/input/encrypted-aes-128.pdf"));
        byte[] v = valid();
        for (int cut = 0; cut < v.length; cut += 997) run(Arrays.copyOf(v, cut));
        Random rnd = new Random(20261126L);
        String[] inserts = {"[", "[[[[[[[[", "<<", ">>", " 0 R", " 1 0 R ", "/Type /ObjStm", "/Size 99999999999", "endobj", "stream\n",
            "/Extends 3 0 R", "/Length 999999999", "/Filter /FlateDecode"};
        for (int i = 0; i < 200; i++) {
            byte[] b = seeds.get(i % seeds.size()).clone();
            int n = 1 + rnd.nextInt(4);
            for (int k = 0; k < n; k++) {
                int at = rnd.nextInt(Math.max(1, b.length));
                switch (rnd.nextInt(4)) {
                    case 0:
                        if (b.length > 0) b[at] = (byte) rnd.nextInt(256);
                        break;
                    case 1:
                        b = Arrays.copyOf(b, at);
                        break;
                    case 2: {
                        byte[] ins = inserts[rnd.nextInt(inserts.length)].getBytes(StandardCharsets.ISO_8859_1);
                        byte[] nb = new byte[b.length + ins.length];
                        System.arraycopy(b, 0, nb, 0, at);
                        System.arraycopy(ins, 0, nb, at, ins.length);
                        System.arraycopy(b, at, nb, at + ins.length, b.length - at);
                        b = nb;
                        break;
                    }
                    default: {
                        int len = Math.min(b.length - at, 1 + rnd.nextInt(512));
                        byte[] nb = new byte[b.length + len];
                        System.arraycopy(b, 0, nb, 0, at + len);
                        System.arraycopy(b, at, nb, at + len, b.length - at);
                        b = nb;
                    }
                }
            }
            run(b);
        }
    }

    private static void run(byte[] d) {
        long t0 = System.nanoTime();
        try {
            EidPades.validatePdf(d, golden());
        } catch (ValidatePdfException e) {
            // typed — fine
        }
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue("took " + ms + " ms", ms < 10_000);
    }
}
