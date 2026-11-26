package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import mn.eidmongolia.eid.HashAlgorithm;
import mn.eidmongolia.eid.SealCertificate;
import mn.eidmongolia.eid.SealResult;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * Organisation seal stamp (APPEARANCE_SPEC.md §6, golden v12/v13) and Prepare's docId rule (§6.6) — ports of the Go
 * reference tests core.TestSealQRContent, TestResolveDocID, TestDocIDFromStampsEarliest / Malformed,
 * TestCitizenOnlyDocIDUnchanged, TestPrepareDocIDRule, TestSealPDFStillQRless, TestSealPDFInvisible,
 * TestSealPDFAutoPlacement, TestSealPDFSmallPages and TestSealPDFNearSizeLimit (byte identity on the golden vectors).
 */
public class SealStampTest {
    static final String QR_SEAL_DOC_ID = "8c9d0e1f-2a3b-4c4d-8e5f-6a7b8c9d0e1f"; // golden seal-qr-visible
    static final String PAGE_DOC_ID = "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f"; // golden quartz-pdf13 (verify page)
    static final String OTHER_DOC_ID = "0f1e2d3c-4b5a-4968-8776-5a4b3c2d1e0f";
    static final String ORG = "NTRMN-0000000";

    private final Json.Obj m = Golden.manifest();
    private final byte[] citizen = Golden.pem("pki/citizen.pem");
    private final byte[] seal = Golden.pem("pki/seal.pem");
    private final List<byte[]> chain = Golden.chain();
    private final Date signingTime = Golden.time(m.getString("signingTime"));

    // ── §6.5 content: the citizen stamp with the seal label, never a role line; §6.2 has no marker ──

    @Test
    public void sealQrContent() {
        String url = "https://ca.eidmongolia.mn/verify/" + QR_SEAL_DOC_ID + "/1";
        VerifyPage.Writer w = new VerifyPage.Writer(PageFont.regular(), PageFont.bold());
        Map<String, String[]> labels = Map.of("mn", new String[] {"eID Mongolia-аар зурсан", "eID Mongolia-аар тамгалсан"},
            "en", new String[] {"Signed with eID Mongolia", "Sealed with eID Mongolia"});
        for (String lang : new String[] {"mn", "en"}) {
            for (int rot : new int[] {0, 90, 180, 270}) {
                String cit = new String(Appearance.content(new Appearance.Params(22000, 6400, rot, "TEST ONLY Golden Org LLC", "", lang,
                    "2026-10-14 12:00 (+08)", url, false)), StandardCharsets.ISO_8859_1);
                String s = new String(Appearance.content(new Appearance.Params(22000, 6400, rot, "TEST ONLY Golden Org LLC",
                    "Захирал, Тест ХХК", lang, "2026-10-14 12:00 (+08)", url, true)), StandardCharsets.ISO_8859_1);
                String want = cit.replaceFirst(java.util.regex.Pattern.quote(w.glyphHex(1, labels.get(lang)[0])),
                    w.glyphHex(1, labels.get(lang)[1]));
                assertEquals(lang + " rot " + rot, want, s);
                assertTrue(s.startsWith("/EIDVerify <</URL (" + url + ")>> BDC\n"));
                String plain = new String(Appearance.content(new Appearance.Params(22000, 6400, rot, "TEST ONLY Golden Org LLC",
                    "Захирал, Тест ХХК", lang, "2026-10-14 12:00 (+08)", "", true)), StandardCharsets.ISO_8859_1);
                assertFalse(plain.contains("EIDVerify"));
                assertFalse(plain.contains(" re\n"));
            }
        }
        try {
            Appearance.content(new Appearance.Params(22000, 4499, 0, "TEST ONLY Golden Org LLC", "", "mn", "2026-10-14 12:00 (+08)", url, true));
            fail("44.99 pt");
        } catch (AppearanceException e) {
            // expected
        }
        Appearance.content(new Appearance.Params(22000, 4500, 0, "TEST ONLY Golden Org LLC", "", "mn", "2026-10-14 12:00 (+08)", url, true));
    }

    // ── §6.6 docId rule ──

    private PrepareOptions.Builder citizenOpts(String docId, boolean visible) {
        PrepareOptions.Builder b = PrepareOptions.builder(citizen).chain(chain).signingTime(signingTime).docId(docId);
        if (visible) b.appearance(new SignatureAppearance(340, 36, 220, 64));
        return b;
    }

    private static void expectCode(String code, Runnable r) {
        try {
            r.run();
            fail("expected " + code);
        } catch (EidPadesException e) {
            assertEquals(e.getMessage(), code, e.code());
        }
    }

    /** Precheck's stamp sources (checked e-Seal signature → position); issuers = the embedded ones + golden 04 (= chain[0]). */
    private static Map<Integer, Integer> seals(byte[] doc) {
        List<mn.eidmongolia.eid.internal.Cert> issuers = new ArrayList<>(EidChain.issuers());
        issuers.add(mn.eidmongolia.eid.internal.Cert.parse(Golden.pem("pki/04.pem")));
        return Precheck.run(doc, issuers).seals;
    }

    @Test
    public void resolveDocId() {
        byte[] sealQr = Golden.output("seal-qr-visible"); // marker 8c9d…, no verify page
        byte[] sealV12 = Golden.output("seal-visible"); // neither page nor marker
        byte[] invisible = Golden.output("quartz-pdf13-nopage"); // invisible citizen, no page
        byte[] withPage = Golden.output("quartz-pdf13"); // verify page 6f0c…
        assertEquals(Collections.singletonMap(seals(sealQr).keySet().iterator().next(), 1), seals(sealQr));
        assertTrue(seals(invisible).isEmpty());
        assertEquals(QR_SEAL_DOC_ID, Precheck.docIdFromStamps(sealQr, seals(sealQr)));
        assertNull(Precheck.docIdFromStamps(sealV12, seals(sealV12)));
        // (2.1) verify page
        assertEquals(PAGE_DOC_ID, Pades.prepare(withPage, citizenOpts(null, false).build()).docId());
        expectCode("REQUEST_INVALID", () -> Pades.prepare(withPage, citizenOpts(OTHER_DOC_ID, false).build()));
        // (2.2) marker
        assertEquals(QR_SEAL_DOC_ID, Pades.prepare(sealQr, citizenOpts(null, false).build()).docId());
        assertEquals(QR_SEAL_DOC_ID, Pades.prepare(sealQr, citizenOpts(QR_SEAL_DOC_ID, false).build()).docId());
        // (3) nothing found → the caller's docId (opt-in); (4) nothing → none, never random on a signed document.
        assertEquals(OTHER_DOC_ID, Pades.prepare(sealV12, citizenOpts(OTHER_DOC_ID, false).build()).docId());
        assertEquals("", Pades.prepare(sealV12, citizenOpts(null, false).build()).docId());
        assertEquals("", Pades.prepare(invisible, citizenOpts(null, false).build()).docId());
        // (1) unsigned → the caller's or a random one.
        byte[] unsigned = Golden.file("input/quartz-pdf13.pdf");
        assertEquals(OTHER_DOC_ID, Pades.prepare(unsigned, citizenOpts(OTHER_DOC_ID, false).build()).docId());
        String rnd = Pades.prepare(unsigned, citizenOpts(null, false).build()).docId();
        assertTrue(rnd, Precheck.UUID_RE.matcher(rnd).matches());
    }

    /** Go TestPrepareDocIDRule. */
    @Test
    public void prepareDocIdRule() {
        byte[] sealQr = Golden.output("seal-qr-visible");
        Prepared p = Pades.prepare(sealQr, citizenOpts(null, true).build());
        assertEquals(QR_SEAL_DOC_ID, p.docId());
        assertTrue(contains(tail(p, sealQr.length), marker(QR_SEAL_DOC_ID)));
        assertEquals(QR_SEAL_DOC_ID, Pades.prepare(sealQr, citizenOpts(null, false).build()).docId());
        for (boolean visible : new boolean[] {true, false}) {
            expectCode("REQUEST_INVALID", () -> Pades.prepare(sealQr, citizenOpts(OTHER_DOC_ID, visible).build()));
        }
        byte[] sealV12 = Golden.output("seal-visible");
        expectCode("REQUEST_INVALID", () -> Pades.prepare(sealV12, citizenOpts(null, true).build()));
        Prepared q = Pades.prepare(sealV12, citizenOpts(OTHER_DOC_ID, true).build());
        assertEquals(OTHER_DOC_ID, q.docId());
        assertTrue(contains(tail(q, sealV12.length), marker(OTHER_DOC_ID)));
    }

    /**
     * Go TestCitizenOnlyDocIDUnchanged / stampSources: step 2.2 is e-Seal only — a citizen stamp's /EIDVerify marker is
     * never a docId source, and a seal's position counts every checked signature. (The Go test signs a fresh citizen
     * document with the golden key, which the vendored PKI does not carry; the rule is proven on the golden outputs.)
     */
    @Test
    public void citizenStampIsNeverADocIdSource() {
        byte[] citizenStamp = Golden.output("quartz-pdf13-visible"); // citizen stamp with marker + verify page
        assertTrue(contains(citizenStamp, Golden.ascii("/EIDVerify <</URL (")));
        assertTrue(seals(citizenStamp).isEmpty());
        assertNull(Precheck.docIdFromStamps(citizenStamp, seals(citizenStamp)));
        byte[] citizenThenSeal = Golden.output("citizen-then-seal-qr");
        Map<Integer, Integer> s = seals(citizenThenSeal);
        assertEquals(1, s.size());
        assertEquals(Integer.valueOf(2), s.values().iterator().next());
        assertEquals("8a9b0c1d-2e3f-4a5b-8c6d-7e8f9a0b1c2d", Precheck.docIdFromStamps(citizenThenSeal, s));
    }

    private static byte[] tail(Prepared p, int from) {
        byte[] pdf = PrepState.decode(p.stateRaw()).pdf;
        return Arrays.copyOfRange(pdf, from, pdf.length);
    }

    private static byte[] marker(String id) {
        return ("/EIDVerify <</URL (" + Precheck.VERIFY_URL + id + "/2)>> BDC\n").getBytes(StandardCharsets.ISO_8859_1);
    }

    static boolean contains(byte[] h, byte[] n) {
        return PdfReader.indexOf(h, n, 0) >= 0;
    }

    // ── docIdFromStamps on synthetic documents (Go stampPDF) ──

    /** Go rawPDF: objects 1…n, classic xref. */
    static byte[] rawPdf(String... objs) {
        StringBuilder b = new StringBuilder("%PDF-1.7\n");
        int[] offs = new int[objs.length];
        for (int i = 0; i < objs.length; i++) {
            offs[i] = b.length();
            b.append(i + 1).append(" 0 obj\n").append(objs[i]).append("\nendobj\n");
        }
        int x = b.length();
        b.append("xref\n0 ").append(objs.length + 1).append("\n0000000000 65535 f\r\n");
        for (int o : offs) b.append(String.format("%010d 00000 n\r\n", o));
        b.append("trailer\n<< /Size ").append(objs.length + 1).append(" /Root 1 0 R >>\nstartxref\n").append(x).append("\n%%EOF\n");
        return b.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    static byte[] stampPdf(List<String> objs) {
        List<String> all = new ArrayList<>(Arrays.asList("<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>"));
        all.addAll(objs);
        return rawPdf(all.toArray(new String[0]));
    }

    static String stampStream(String docId, int rev, String extra) {
        String c = "/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/" + docId + "/" + rev + ")>> BDC\nEMC\n";
        return "<< /Length " + c.length() + extra + " >>\nstream\n" + c + "endstream";
    }

    static String stampStreamLenRef(String docId, int rev, int lenObj) {
        String c = "/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/" + docId + "/" + rev + ")>> BDC\nEMC\n";
        return "<< /Length " + lenObj + " 0 R >>\nstream\n" + c + "endstream";
    }

    static String stampWidget(String sig, String form) {
        return "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0] /P 3 0 R /F 4 /FT /Sig /T (S) /V " + sig + " /AP << /N " + form + " 0 R >> >>";
    }

    static String stampSig(int end) {
        return "<< /Type /Sig /ByteRange [0 10 20 " + (end - 20) + "] /Contents <00> >>";
    }

    private static Map<Integer, Integer> map(int... kv) {
        Map<Integer, Integer> out = new HashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put(kv[i], kv[i + 1]);
        return out;
    }

    @SafeVarargs
    private static <T> List<T> concat(List<T> a, T... extra) {
        List<T> out = new ArrayList<>(a);
        out.addAll(Arrays.asList(extra));
        return out;
    }

    @Test
    public void docIdFromStampsEarliest() {
        String later = "11111111-1111-4111-8111-111111111111";
        String earlier = "22222222-2222-4222-8222-222222222222";
        String forged = "33333333-3333-4333-8333-333333333333";
        // 4 widget (later, lower number) → 6 sig (end 200, position 2); 7 widget (earlier, higher number) → 9 sig (end 50, position 1).
        List<String> base = Arrays.asList(stampWidget("6 0 R", "5"), stampStream(later, 2, ""), stampSig(200), stampWidget("9 0 R", "8"),
            stampStream(earlier, 1, ""), stampSig(50));
        Map<Integer, Integer> seals = map(6, 2, 9, 1);
        Object[][] cases = {
            {"earliest has the higher number", base, seals, earlier},
            {"earliest marker rev 2 (position 1) — ignored", Arrays.asList(stampWidget("6 0 R", "5"), stampStream(later, 2, ""), stampSig(200),
                stampWidget("9 0 R", "8"), stampStream(earlier, 2, ""), stampSig(50)), seals, later},
            {"earliest is a citizen (not in seals) — ignored", base, map(6, 2), later},
            {"direct /V dict — ignored", concat(base, "<< /FT /Sig /V << /Type /Sig /ByteRange [0 0 0 0] /Contents <00> >> /AP << /N 11 0 R >> >>",
                stampStream(forged, 1, "")), seals, earlier},
            {"borrowed /V (2 widgets on 9) — 9 ignored", concat(base, stampWidget("9 0 R", "11"), stampStream(forged, 1, "")), seals, later},
            {"/V to an unchecked signature — ignored", concat(base, stampWidget("12 0 R", "11"), stampStream(forged, 1, ""), stampSig(30)), seals,
                earlier},
            {"/Filter [] — not a candidate", one(earlier, " /Filter []"), map(6, 1), null},
            {"/Filter /FlateDecode — not a candidate", one(earlier, " /Filter /FlateDecode"), map(6, 1), null},
            {"/Filter direct null — candidate", one(earlier, " /Filter null"), map(6, 1), earlier},
            {"/Filter indirect null — not a candidate", one(earlier, " /Filter 7 0 R", "null"), map(6, 1), null},
            {"no seals", base, Collections.emptyMap(), null},
        };
        for (Object[] c : cases) {
            @SuppressWarnings("unchecked")
            List<String> objs = (List<String>) c[1];
            @SuppressWarnings("unchecked")
            Map<Integer, Integer> s = (Map<Integer, Integer>) c[2];
            assertEquals((String) c[0], c[3], Precheck.docIdFromStamps(stampPdf(objs), s));
        }
    }

    private static List<String> one(String docId, String filter, String... extra) {
        return concat(Arrays.asList(stampWidget("6 0 R", "5"), stampStream(docId, 1, filter), stampSig(50)), extra);
    }

    /** Go breakObj: object n unreadable — header generation 0 → 1 (differs from the xref entry); length unchanged. */
    static byte[] breakObj(byte[] doc, int n) {
        String s = new String(doc, StandardCharsets.ISO_8859_1);
        String old = "\n" + n + " 0 obj\n";
        int i = s.indexOf(old);
        if (i < 0 || s.indexOf(old, i + 1) >= 0) throw new IllegalStateException("breakObj " + n);
        return (s.substring(0, i) + "\n" + n + " 1 obj\n" + s.substring(i + old.length())).getBytes(StandardCharsets.ISO_8859_1);
    }

    private static final class Group {
        final List<String> objs;
        final int[] broken;
        final int seal;

        Group(List<String> objs, int[] broken, int seal) {
            this.objs = objs;
            this.broken = broken;
            this.seal = seal;
        }
    }

    private interface Bad {
        Group at(int a, int validSig);
    }

    private static String ref(int n) {
        return n + " 0 R";
    }

    /** e-Seal signature a+3 (end 200) with 2 widgets; the first (a) has /AP a+1 0 R, the second a+4. */
    private static Group twoWidgets(int a, String stream, List<String> extra, int... broken) {
        List<String> objs = new ArrayList<>(Arrays.asList("<< /FT /Sig /V " + ref(a + 3) + " /AP " + ref(a + 1) + " >>",
            "<< /N " + ref(a + 2) + " >>", stream, stampSig(200), stampWidget(ref(a + 3), String.valueOf(a + 2))));
        objs.addAll(extra);
        return new Group(objs, broken, a + 3);
    }

    /** e-Seal signature a+3 (end 200) with a single widget (a): /AP a+1 0 R → /N a+2 0 R. */
    private static Group oneWidget(int a, String stream, List<String> extra, int... broken) {
        List<String> objs = new ArrayList<>(Arrays.asList("<< /FT /Sig /V " + ref(a + 3) + " /AP " + ref(a + 1) + " >>",
            "<< /N " + ref(a + 2) + " >>", stream, stampSig(200)));
        objs.addAll(extra);
        return new Group(objs, broken, a + 3);
    }

    /** Go TestDocIDFromStampsMalformed: only the single-widget candidate's own reads fail; other unreadable objects are skipped. */
    @Test
    public void docIdFromStampsMalformed() {
        String good = "44444444-4444-4444-8444-444444444444";
        String other = "55555555-5555-4555-8555-555555555555";
        List<String> none = Collections.emptyList();
        Object[][] cases = {
            {"(a) indirect /FT unreadable — skipped", (Bad) (a, vs) -> new Group(Arrays.asList("<< /FT " + ref(a + 1) + " /V " + ref(vs)
                + " /AP << /N " + ref(a + 2) + " >> >>", "/Sig", stampStream(other, 1, "")), new int[] {a + 1}, 0), false},
            {"(b) non-seal /V unreadable — skipped", (Bad) (a, vs) -> new Group(Arrays.asList("<< /FT /Sig /V " + ref(a + 1) + " /AP << /N "
                + ref(a + 2) + " >> >>", stampSig(10), stampStream(other, 1, "")), new int[] {a + 1}, 0), false},
            {"(c) 2 widgets, the first's /AP unreadable — skipped", (Bad) (a, vs) -> twoWidgets(a, stampStream(other, 2, ""), none, a + 1), false},
            {"(c) 2 widgets, the first's /N unreadable — skipped", (Bad) (a, vs) -> twoWidgets(a, stampStream(other, 2, ""), none, a + 2), false},
            {"(c) 2 widgets, the first's /Length unreadable — skipped", (Bad) (a, vs) -> twoWidgets(a, stampStreamLenRef(other, 2, a + 5),
                List.of("47"), a + 5), false},
            {"single widget, /AP unreadable — PDF_INVALID", (Bad) (a, vs) -> oneWidget(a, stampStream(other, 2, ""), none, a + 1), true},
            {"single widget, /N unreadable — PDF_INVALID", (Bad) (a, vs) -> oneWidget(a, stampStream(other, 2, ""), none, a + 2), true},
            {"single widget, /Length unreadable — PDF_INVALID", (Bad) (a, vs) -> oneWidget(a, stampStreamLenRef(other, 2, a + 4), List.of("47"),
                a + 4), true},
            {"single widget, indirect /DecodeParms unreadable — PDF_INVALID", (Bad) (a, vs) -> oneWidget(a, stampStream(other, 2, " /DecodeParms "
                + ref(a + 4)), List.of("<< >>"), a + 4), true},
        };
        for (Object[] c : cases) {
            String name = (String) c[0];
            Bad bad = (Bad) c[1];
            boolean failing = (Boolean) c[2];
            int n = bad.at(0, 0).objs.size();
            for (boolean badFirst : new boolean[] {true, false}) {
                int va = badFirst ? 4 + n : 4;
                int ba = badFirst ? 4 : 7;
                Group g = bad.at(ba, va + 2);
                List<String> objs = new ArrayList<>();
                List<String> valid = Arrays.asList(stampWidget(ref(va + 2), String.valueOf(va + 1)), stampStream(good, 1, ""), stampSig(50));
                if (badFirst) {
                    objs.addAll(g.objs);
                    objs.addAll(valid);
                } else {
                    objs.addAll(valid);
                    objs.addAll(g.objs);
                }
                byte[] doc = stampPdf(objs);
                for (int b : g.broken) doc = breakObj(doc, b);
                Map<Integer, Integer> seals = map(va + 2, 1);
                if (g.seal != 0) seals.put(g.seal, 2);
                String got;
                try {
                    got = Precheck.docIdFromStamps(doc, seals);
                } catch (RuntimeException e) {
                    if (!failing) throw new AssertionError(name + " (first=" + badFirst + "): " + e, e);
                    continue;
                }
                if (failing) fail(name + " (first=" + badFirst + "): " + got + ", want an error");
                assertEquals(name + " (first=" + badFirst + ")", good, got);
            }
        }
    }

    // ── sealPdf (Go SealPDF, APPEARANCE_SPEC.md §6.4) ──

    private static final class Stop extends RuntimeException {
        Stop() {
            super("stop");
        }
    }

    /** Go dtbsSealer: records the DTBS and stops (no Complete — only the prepared bytes matter). */
    private static final class DtbsSealer implements Sealer {
        final byte[] cert;
        byte[] digest;

        DtbsSealer(byte[] cert) {
            this.cert = cert;
        }

        @Override
        public SealCertificate certificate(String orgEtsi) {
            return new SealCertificate(orgEtsi, cert, "1", "", "", Instant.EPOCH, Instant.EPOCH, "QUALIFIED");
        }

        @Override
        public SealResult seal(String orgEtsi, byte[] d, HashAlgorithm hash) {
            digest = d;
            throw new Stop();
        }
    }

    private byte[] sealDtbs(byte[] pdf, SealOptions.Builder o) {
        DtbsSealer s = new DtbsSealer(seal);
        try {
            EidPades.sealPdf(s, ORG, pdf, o.signingTime(signingTime).chain(chain).build());
            fail("sealer not called");
        } catch (Stop e) {
            // expected
        }
        return s.digest;
    }

    private PrepareOptions.Builder sealPrepare() {
        return PrepareOptions.builder(seal).chain(chain).signingTime(signingTime);
    }

    /** Go TestSealPDFStillQRless: the default and an explicit appearance draw the QR-less stamp = golden seal-visible(-en). */
    @Test
    public void sealPdfStillQrLess() {
        assertEquals(Golden.caseNamed(m, "seal-visible").getObj("expect").getString("dtbs"),
            Text.hex(sealDtbs(Golden.file("input/libreoffice-contract.pdf"), SealOptions.builder().reason("Нэхэмжлэх"))));
        assertEquals(Golden.caseNamed(m, "seal-visible-en").getObj("expect").getString("dtbs"),
            Text.hex(sealDtbs(Golden.file("input/quartz-pdf13.pdf"), SealOptions.builder()
                .appearance(new SignatureAppearance(0, 340, 36, 220, 64, "en", false)))));
    }

    /** The default sealPdf end to end (TSA/OCSP/CRL replayed): golden seal-visible's output bytes and placement. */
    @Test
    public void sealPdfDefaultGoldenOutput() {
        Json.Obj c = Golden.caseNamed(m, "seal-visible");
        Json.Obj e = c.getObj("expect");
        byte[] sig = Text.unhex(e.getString("signature"));
        Sealer s = new Sealer() {
            @Override
            public SealCertificate certificate(String orgEtsi) {
                return new SealCertificate(orgEtsi, seal, "1", "", "", Instant.EPOCH, Instant.EPOCH, "QUALIFIED");
            }

            @Override
            public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash) {
                assertEquals(e.getString("dtbs"), Text.hex(digest));
                return new SealResult(orgEtsi, sig, "sha256WithRSAEncryption", seal, "QUALIFIED", Instant.EPOCH, "{}");
            }
        };
        Completed res = EidPades.sealPdf(s, ORG, Golden.file("input/libreoffice-contract.pdf"), SealOptions.builder().reason("Нэхэмжлэх")
            .signingTime(signingTime).chain(chain).complete(Golden.completeOptions(m)).build(), Golden.env(Golden.time(m.getString("now")),
            "seal-visible"));
        assertEquals(e.getString("outSha256"), res.outSha256());
        Json.Obj pl = e.getObj("placement");
        assertEquals(new Placement(pl.getInt("page"), pl.getDouble("x"), pl.getDouble("y"), pl.getDouble("width"), pl.getDouble("height"),
            PlacementStatus.valueOf(pl.getString("status").toUpperCase(java.util.Locale.ROOT))), res.placement());
        assertFalse(res.hasPage());
        assertEquals(1, res.revIndex());
    }

    /** Go TestSealPDFInvisible: invisible = the pre-stamp output (the DTBS of a prepare without appearance). */
    @Test
    public void sealPdfInvisible() {
        for (String name : new String[] {"quartz-pdf13.pdf", "libreoffice-contract.pdf"}) {
            byte[] in = Golden.file("input/" + name);
            byte[] got = sealDtbs(in, SealOptions.builder().invisible(true).reason("Нэхэмжлэх")
                .appearance(new SignatureAppearance(36, 36, 220, 64)));
            Prepared old = EidPades.prepare(in, sealPrepare().reason("Нэхэмжлэх").build());
            assertArrayEquals(name, old.dtbs(), got);
            assertNull(old.placement());
        }
    }

    private static void placement(String what, Placement want, Placement got) {
        assertNotNull(what, got);
        assertEquals(what, want, got);
    }

    /** Go TestSealPDFAutoPlacement (placement part): x = 612 − 220 − 36, y = 36; free → requested, footer → moved, full → overlap. */
    @Test
    public void sealPdfAutoPlacement() {
        Object[][] cases = {
            {"quartz-pdf13.pdf", new Placement(1, 356, 36, 220, 64, PlacementStatus.REQUESTED)},
            {"libreoffice-contract.pdf", new Placement(2, 356, 60, 220, 64, PlacementStatus.MOVED)},
            {"full-page.pdf", new Placement(1, 356, 36, 220, 64, PlacementStatus.OVERLAP)},
        };
        for (Object[] c : cases) {
            byte[] in = Golden.file("input/" + c[0]);
            SignatureAppearance a = EidPades.defaultSealAppearance(in);
            Prepared p = EidPades.prepare(in, sealPrepare().appearance(a).build());
            placement((String) c[0], (Placement) c[1], p.placement());
            assertArrayEquals((String) c[0], p.dtbs(), sealDtbs(in, SealOptions.builder()));
        }
    }

    /** One w × h pt page (Go smallPDF without the text line). */
    static byte[] smallPdf(double w, double h) {
        return rawPdf("<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 " + Appearance.num100(Appearance.round100(w)) + " "
                + Appearance.num100(Appearance.round100(h)) + "] >>");
    }

    /** Go TestSealPDFSmallPages: a 58 mm receipt → 156 × 64 at x = 4; a tiny page → invisible; an explicit rect that does not fit → REQUEST_INVALID. */
    @Test
    public void sealPdfSmallPages() {
        byte[] receipt = smallPdf(164, 600);
        SignatureAppearance a = EidPades.defaultSealAppearance(receipt);
        Prepared p = EidPades.prepare(receipt, sealPrepare().appearance(a).build());
        placement("receipt", new Placement(1, 4, 36, 156, 64, PlacementStatus.REQUESTED), p.placement());
        assertArrayEquals(p.dtbs(), sealDtbs(receipt, SealOptions.builder()));

        byte[] tiny = smallPdf(40, 60);
        assertArrayEquals("tiny → invisible", EidPades.prepare(tiny, sealPrepare().build()).dtbs(), sealDtbs(tiny, SealOptions.builder()));
        expectCode("REQUEST_INVALID", () -> sealDtbs(tiny, SealOptions.builder().appearance(new SignatureAppearance(0, 0, 40, 60))));
    }

    /** Go padPDF: an incremental update with one unreferenced stream object of n bytes (classic xref). */
    static byte[] padPdf(byte[] doc, int n) {
        PdfReader r = PdfReader.open(doc);
        PdfRef root = r.trailer.get("Root").ref();
        PdfRef info = r.trailer.get("Info").ref();
        long num = r.trailer.get("Size").asLong();
        int prev = PdfReader.findStartXref(doc);
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(doc);
        b.writeBytes(Golden.ascii("\n"));
        int off = b.size();
        b.writeBytes(Golden.ascii(num + " 0 obj\n<< /Length " + n + " >>\nstream\n"));
        byte[] zeros = new byte[n];
        Arrays.fill(zeros, (byte) '0');
        b.writeBytes(zeros);
        b.writeBytes(Golden.ascii("\nendstream\nendobj\n"));
        int x = b.size();
        String infoRef = info == null ? "" : " /Info " + info.id() + " 0 R";
        b.writeBytes(Golden.ascii(String.format("xref\n%d 1\n%010d 00000 n \ntrailer\n<< /Size %d /Root %d 0 R%s /Prev %d >>\nstartxref\n%d\n%%%%EOF\n",
            num, off, num + 1, root.id(), infoRef, prev, x)));
        return b.toByteArray();
    }

    private int overhead(byte[] doc, SignatureAppearance a) {
        Prepared p = EidPades.prepare(doc, sealPrepare().reason("Нэхэмжлэх").appearance(a).build());
        return PrepState.decode(p.stateRaw()).pdf.length - doc.length;
    }

    /** Go TestSealPDFNearSizeLimit: the automatic stamp's fonts would exceed the size limit → invisible; explicit → PDF_TOO_LARGE. */
    @Test
    public void sealPdfNearSizeLimit() {
        byte[] base = Golden.file("input/quartz-pdf13.pdf");
        byte[] probe = padPdf(base, 1000);
        int inv = overhead(probe, null);
        int vis = overhead(probe, EidPades.defaultSealAppearance(probe));
        assertTrue("overheads " + inv + " / " + vis, vis - inv >= 40_000);
        int target = Pades.MAX_OUTPUT_BYTES - (256 << 10) - (inv + vis) / 2;
        byte[] doc = padPdf(base, 1000 + target - probe.length);
        assertTrue("size " + doc.length + " target " + target, Math.abs(doc.length - target) <= 100 && doc.length <= Pades.MAX_INPUT_BYTES);
        expectCode("PDF_TOO_LARGE", () -> EidPades.prepare(doc, sealPrepare().reason("Нэхэмжлэх").appearance(EidPades.defaultSealAppearance(doc))
            .build()));
        assertArrayEquals(EidPades.prepare(doc, sealPrepare().reason("Нэхэмжлэх").build()).dtbs(),
            sealDtbs(doc, SealOptions.builder().reason("Нэхэмжлэх")));
        expectCode("PDF_TOO_LARGE", () -> sealDtbs(doc, SealOptions.builder().reason("Нэхэмжлэх")
            .appearance(new SignatureAppearance(340, 36, 220, 64))));
    }
}
