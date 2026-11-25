package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** Stable error codes (Go `pades/errors.go`) for the light prechecks and complete's input checks. */
public class ErrorTest {
    private final byte[] citizen = Golden.pem("pki/citizen.pem");
    private final List<byte[]> chain = Arrays.asList(Golden.pem("pki/04.pem"), Golden.pem("pki/03.pem"), Golden.pem("pki/02.pem"));
    private final byte[] pdf = Golden.file("input/quartz-pdf13.pdf");
    private static final String DOC = "0b2f8a1e-6c3d-4e5f-8a9b-1c2d3e4f5a6b";
    private static final Date T = new Date(1_791_950_400_000L);

    static String code(Runnable f) {
        try {
            f.run();
            return "OK";
        } catch (EidPadesException e) {
            return e.code();
        }
    }

    private PrepareOptions.Builder base() {
        return PrepareOptions.builder(citizen).chain(chain);
    }

    @Test
    public void prepareCodes() {
        PrepareOptions o = base().build();
        assertEquals("PDF_TOO_LARGE", code(() -> EidPades.prepare(new byte[Pades.MAX_INPUT_BYTES + 1], o)));
        assertEquals("PDF_INVALID", code(() -> EidPades.prepare(Golden.ascii("hello"), o)));
        assertEquals("SIGNER_INVALID", code(() -> EidPades.prepare(pdf, PrepareOptions.builder(new byte[] {1, 2, 3}).build())));
        assertEquals("SIGNER_INVALID", code(() -> EidPades.prepare(pdf, PrepareOptions.builder(citizen).build()))); // test issuer not embedded
        assertEquals("REQUEST_INVALID", code(() -> EidPades.prepare(pdf, base().docId("NOT-A-UUID").build())));
        assertEquals("REQUEST_INVALID", code(() -> EidPades.prepare(pdf, base().lang("de").build())));
        assertEquals("REQUEST_INVALID", code(() -> EidPades.prepare(pdf, base().verifyPage(true).build())));
        assertEquals("REQUEST_INVALID", code(() -> EidPades.prepare(pdf, base().verifyPagePosition("middle").build())));
        assertEquals("PDF_INVALID", code(() -> EidPades.prepare(Golden.ascii("%PDF-1.4\nbroken"), o)));
        assertEquals("OK", code(() -> EidPades.prepare(pdf, o)));
    }

    private static SignatureAppearance at(int page, double x, double y, double width, double height, String lang) {
        return new SignatureAppearance(page, x, y, width, height, lang, false);
    }

    /** Go TestAppearanceRejects — APPEARANCE_SPEC.md §1, §3: bad placement/size or text that does not fit → REQUEST_INVALID. */
    @Test
    public void appearanceRejects() {
        SignatureAppearance ok = new SignatureAppearance(36, 36, 220, 64); // quartz-pdf13: 612 × 792, 1 page
        Map<String, PrepareOptions> cases = new LinkedHashMap<>();
        cases.put("page missing", vis(at(2, 36, 36, 220, 64, null), null, null));
        cases.put("negative page", vis(at(-1, 36, 36, 220, 64, null), null, null));
        cases.put("off the page (x)", vis(at(0, 500, 36, 220, 64, null), null, null));
        cases.put("off the page (y)", vis(at(0, 36, 760, 220, 64, null), null, null));
        cases.put("too low (QR < 1 pt)", vis(at(0, 36, 36, 220, 44, null), null, null));
        cases.put("too narrow (text)", vis(at(0, 36, 36, 90, 64, null), null, null));
        cases.put("zero width", vis(at(0, 36, 36, 0, 64, null), null, null));
        cases.put("NaN", vis(at(0, Double.NaN, 36, 220, 64, null), null, null));
        cases.put("> 14400", vis(at(0, 36, 36, 220, 14401, null), null, null));
        cases.put("lang", vis(at(0, 36, 36, 220, 64, "de"), null, null));
        cases.put("/Name not writable", vis(ok, "a stream b", null));
        cases.put("role control char", vis(ok, null, "a\u200eb"));
        for (Map.Entry<String, PrepareOptions> c : cases.entrySet()) {
            assertEquals(c.getKey(), "REQUEST_INVALID", code(() -> EidPades.prepare(pdf, c.getValue())));
        }
        // Minimum (45 pt high) is accepted and differs from the invisible DTBS (same docId and signing time).
        Prepared p45 = EidPades.prepare(pdf, base().verifyPage(true).fileName("test.pdf").docId(DOC).signingTime(T)
            .appearance(at(0, 36, 36, 220, 45, null)).build());
        Prepared inv = EidPades.prepare(pdf, base().verifyPage(true).fileName("test.pdf").docId(DOC).signingTime(T).build());
        assertFalse(Arrays.equals(p45.dtbs(), inv.dtbs()));
    }

    private PrepareOptions vis(SignatureAppearance a, String signerName, String claimedRole) {
        return base().verifyPage(true).fileName("test.pdf").signerName(signerName).claimedRole(claimedRole).appearance(a).build();
    }

    @Test
    public void completeCodes() {
        Prepared prep = EidPades.prepare(pdf, base().build());
        CompleteOptions noNet = CompleteOptions.builder().transport((m, u, c, b) -> {
            throw new IOException("offline");
        }).build();
        assertEquals("STATE_INVALID", code(() -> EidPades.complete(new byte[] {1, 2}, new byte[256], noNet)));
        byte[] tampered = prep.state();
        tampered[tampered.length - 10]++;
        assertEquals("STATE_INVALID", code(() -> EidPades.complete(tampered, new byte[256], noNet)));
        assertEquals("SIGNATURE_INVALID", code(() -> EidPades.complete(prep.state(), new byte[256], noNet)));
    }

    @Test
    public void textRules() {
        assertEquals("<4a6f686e20446f65>", SignatureRevision.sigText("  John Doe ", 120));
        assertEquals("<feff041104300442>", SignatureRevision.sigText("Бат", 120));
        assertNull(SignatureRevision.sigText("a\u0007b", 120));
        assertNull(SignatureRevision.sigText("x endobj", 120));
        assertNull(SignatureRevision.sigText("x".repeat(128), 127));
        assertEquals("(D:20261014120000+08'00')", SignatureRevision.pdfDate(new Date(1_791_950_400_000L)));
        assertEquals("14.1 KB", VerifyPage.humanSize(14452));
        assertEquals("ca.eidmongolia.mn/verify", VerifyPage.urlHost("https://ca.eidmongolia.mn/verify/abc"));
        assertNull(Pades.cleanFileName("\u200b \u0007"));
        assertNull(Pades.cleanFileName("a".repeat(121)));
        assertEquals("Гэрээ.pdf", Pades.cleanFileName(" Гэрээ.pdf\u0000 "));
    }

    @Test
    public void jsonStrict() {
        assertEquals("x", ((Json.Obj) Json.parse(Golden.ascii("{\"a\":\"x\"}"))).getString("a"));
        for (String bad : new String[] {"{\"a\":1,}", "[1 2]", "{\"a\":01}", "\"\\x\"", "{} x", "{\"a\":tru}"}) {
            assertEquals(bad, "error", parseOrError(bad));
        }
    }

    private static String parseOrError(String s) {
        try {
            Json.parse(Golden.ascii(s));
            return "ok";
        } catch (IllegalArgumentException e) {
            return "error";
        }
    }
}
