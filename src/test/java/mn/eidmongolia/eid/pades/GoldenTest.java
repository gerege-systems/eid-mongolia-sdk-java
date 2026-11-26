package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Ocsp;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * Conformance against the Go reference golden vectors (`golden/SOURCE` = eid-mongolia-sdk-go tag): every case must
 * reproduce prepare (docId, digest, DTBS, signedAttrs, prepared PDF, ByteRange) and complete (output PDF sha256 = byte
 * identity, CMS, revision hashes) with the manifest's citizen signature, replayed TSA/OCSP/CRL responses, fixed clock and
 * nonce.
 */
public class GoldenTest {
    private final Json.Obj m = Golden.manifest();
    private final byte[] citizen = Golden.pem("pki/citizen.pem");
    private final List<byte[]> chain = Arrays.asList(Golden.pem("pki/04.pem"), Golden.pem("pki/03.pem"), Golden.pem("pki/02.pem"));
    private final byte[] root = Golden.pem("pki/root.pem");

    private static List<Json.Obj> cases(Json.Obj m) {
        List<Json.Obj> out = new ArrayList<>();
        for (Object o : m.getArr("cases")) out.add((Json.Obj) o);
        return out;
    }

    @Test
    public void goldenCases() {
        List<Json.Obj> cases = cases(m);
        Date signingTime = Golden.time(m.getString("signingTime"));
        Date now = Golden.time(m.getString("now"));
        int completed = 0;
        Map<String, byte[]> outputs = new HashMap<>(); // case:<name> inputs = this run's own earlier outputs
        for (Json.Obj c : cases) {
            String name = c.getString("name");
            String in = c.getString("input");
            byte[] input;
            if (in.startsWith("case:")) {
                input = outputs.get(in.substring(5));
                if (input == null) throw new IllegalStateException(name + ": no output of " + in);
            } else {
                input = Golden.file(in);
            }
            Json.Obj p = c.getObj("prepare");
            Json.Obj e = c.getObj("expect");
            assertEquals(name + " inputSha256", e.getString("inputSha256"), Text.hex(Cms.sha256(input)));
            Json.Obj ap = p.optObj("appearance");
            SignatureAppearance appearance = ap == null ? null : new SignatureAppearance(ap.optInt("page", 0), ap.getDouble("x"),
                ap.getDouble("y"), ap.getDouble("width"), ap.getDouble("height"), ap.optNonEmpty("lang"), ap.optBool("exact", false));
            PrepareOptions opts = PrepareOptions.builder(citizen).chain(chain).signingTime(signingTime)
                .signerName(p.optNonEmpty("signerName")).reason(p.optNonEmpty("reason")).claimedRole(p.optNonEmpty("claimedRole"))
                .docId(p.optNonEmpty("docId")).verifyPage(p.optBool("verifyPage", false)).fileName(p.optNonEmpty("fileName"))
                .lang(p.optNonEmpty("lang")).verifyPagePosition(p.optNonEmpty("verifyPagePosition")).appearance(appearance).build();

            // suggestPlacement (PLACEMENT_SPEC §6b, golden v7) field-for-field, before prepare (Go golden_test order).
            PlacementSuggestion suggestion = null;
            if (appearance != null) {
                String wantErr = e.optNonEmpty("suggestionError");
                try {
                    PlacementSuggestion s = EidPades.suggestPlacement(input, appearance);
                    suggestion = s;
                    if (wantErr != null) fail(name + ": suggestPlacement succeeded, Go failed with " + wantErr);
                    Json.Obj ws = e.optObj("suggestion");
                    if (ws == null) throw new IllegalStateException(name + ": visible case without expect.suggestion");
                    assertEquals(name + " suggestion",
                        Arrays.asList((double) ws.getInt("page"), ws.getDouble("x"), ws.getDouble("y"), ws.getDouble("width"),
                            ws.getDouble("height"), ws.getDouble("pageWidth"), ws.getDouble("pageHeight"), (double) ws.getInt("pageCount")),
                        Arrays.asList((double) s.page(), s.x(), s.y(), s.width(), s.height(), s.pageWidth(), s.pageHeight(), (double) s.pageCount()));
                    assertEquals(name + " suggestion status", ws.getString("status"), s.status().wire());
                    List<PlacementSuggestion.PageSize> wp = new ArrayList<>();
                    for (Object o : ws.getArr("pages")) {
                        Json.Obj ps = (Json.Obj) o;
                        wp.add(new PlacementSuggestion.PageSize(ps.getDouble("width"), ps.getDouble("height")));
                    }
                    assertEquals(name + " suggestion pages", wp, s.pages());
                } catch (EidPadesException x) {
                    assertEquals(name + " suggestPlacement (" + x.getMessage() + ")", wantErr, x.code());
                }
            }
            String want = e.optNonEmpty("error");
            Prepared prep;
            try {
                prep = Pades.prepare(input, opts);
            } catch (EidPadesException x) {
                assertEquals(name + " error (" + x.getMessage() + ")", want, x.code());
                continue;
            }
            if (want != null) fail(name + ": expected " + want);
            PrepState st = PrepState.decode(prep.stateRaw());
            assertEquals(name + " docId", e.getString("docId"), prep.docId());
            assertEquals(name + " digest", e.getString("digest"), Text.hex(prep.digest()));
            assertEquals(name + " signedAttrs", e.getString("signedAttrs"), Text.hex(st.signedAttrs));
            assertEquals(name + " dtbs", e.getString("dtbs"), Text.hex(prep.dtbs()));
            assertEquals(name + " preparedSha256", e.getString("preparedSha256"), Text.hex(Cms.sha256(st.pdf)));
            List<Object> br = e.getArr("byteRange");
            long[] wantBr = new long[4];
            for (int i = 0; i < 4; i++) wantBr[i] = ((Json.Num) br.get(i)).longValue();
            assertArrayEquals(name + " byteRange", wantBr, st.byteRange);
            // PLACEMENT_SPEC.md: every visible case reports where the stamp went (golden v5: moved / overlap).
            Json.Obj wantPl = e.optObj("placement");
            assertEquals(name + " placement", ap != null, wantPl != null);
            Placement pl = prep.placement();
            assertEquals(name + " placement",
                wantPl == null ? null : Arrays.asList((double) wantPl.getInt("page"), wantPl.getDouble("x"), wantPl.getDouble("y"),
                    wantPl.getDouble("width"), wantPl.getDouble("height")),
                pl == null ? null : Arrays.asList((double) pl.page(), pl.x(), pl.y(), pl.width(), pl.height()));
            assertEquals(name + " placement status", wantPl == null ? null : wantPl.getString("status"), pl == null ? null : pl.status().wire());
            // suggestion ⊇ placement, except page0-two-verify (unsigned input: suggestPlacement has no docId, §6b).
            if (appearance != null) {
                if (suggestion == null) throw new IllegalStateException(name + ": prepare ok, suggestPlacement failed");
                if (!name.equals("page0-two-verify")) {
                    assertEquals(name + " suggestion ≠ placement", new Placement(suggestion.page(), suggestion.x(), suggestion.y(),
                        suggestion.width(), suggestion.height(), suggestion.status()), pl);
                }
            }

            Completed res = Pades.complete(prep.stateRaw(), Text.unhex(e.getString("signature")),
                CompleteOptions.builder().tsaUrl("http://tsa.pki.test/").roots(Collections.singletonList(root)).transport(Golden.replay(m)).build(),
                Golden.env(now, name));
            assertEquals(name + " cmsSha256", e.getString("cmsSha256"), Text.hex(Cms.sha256(res.cmsRaw())));
            assertEquals(name + " sigRevSha256", e.getString("sigRevSha256"), res.sigRevSha256());
            assertEquals(name + " revIndex", e.getInt("revIndex"), res.revIndex());
            assertEquals(name + " hasPage", e.optBool("hasPage", false), res.hasPage());
            assertEquals(name + " pageSha256", e.optNonEmpty("pageSha256"), res.pageSha256());
            List<String> wantPrior = new ArrayList<>();
            List<Object> prior = e.optArr("priorCmsSha256");
            if (prior != null) for (Object o : prior) wantPrior.add((String) o);
            assertEquals(name + " priorCmsSha256", wantPrior, res.priorCmsSha256());
            assertEquals(name + " priorRevisionSha256", revisions(cases, in), res.priorRevisionSha256());
            assertEquals(name + " outSha256", e.getString("outSha256"), res.outSha256());
            assertEquals(name + " claimedRole", p.optNonEmpty("claimedRole"), res.claimedRole());
            checkRegistration(name, res, p.optNonEmpty("fileName"));
            outputs.put(name, res.pdfRaw());
            completed++;
        }
        int okCases = 0;
        int exactCases = 0;
        for (Json.Obj c : cases) {
            if (c.getObj("expect").optString("error").isEmpty()) okCases++;
            Json.Obj ap = c.getObj("prepare").optObj("appearance");
            if (ap != null && ap.optBool("exact", false)) exactCases++;
        }
        assertTrue("no complete case ran", okCases > 0);
        assertEquals("completed cases", okCases, completed);
        assertTrue("golden v7 exact cases", exactCases >= 5);

        // Visible signature on a signed document without a verify page (no docId) → REQUEST_INVALID.
        byte[] noPage = outputs.get("quartz-pdf13-nopage");
        if (noPage == null) throw new IllegalStateException("quartz-pdf13-nopage output");
        try {
            Pades.prepare(noPage, PrepareOptions.builder(citizen).chain(chain).signingTime(signingTime)
                .appearance(new SignatureAppearance(36, 36, 220, 64)).build());
            fail("visible without docId: expected REQUEST_INVALID");
        } catch (EidPadesException x) {
            assertEquals("visible without docId", "REQUEST_INVALID", x.code());
        }
    }

    /** Prior signatures' revision hashes = each earlier case's own sigRevSha256 along the "case:<prev>" chain. */
    private static List<String> revisions(List<Json.Obj> cases, String input) {
        if (!input.startsWith("case:")) return new ArrayList<>();
        String prevName = input.substring(5);
        for (Json.Obj c : cases) {
            if (c.getString("name").equals(prevName)) {
                List<String> out = revisions(cases, c.getString("input"));
                out.add(c.getObj("expect").getString("sigRevSha256"));
                return out;
            }
        }
        throw new IllegalStateException("no case " + prevName);
    }

    private static void expectRequestInvalid(String name, Runnable r) {
        try {
            r.run();
            fail(name);
        } catch (EidPadesException.RequestInvalid e) {
            // expected
        }
    }

    /** Completed.registration = Go pades.Registration. */
    private static void checkRegistration(String name, Completed done, String fileName) {
        assertEquals(name + " fileName", Pades.cleanFileName(fileName), done.fileName());
        if (done.fileName() == null || done.revIndex() == 1 && !done.hasPage()) {
            expectRequestInvalid(name + ": registration without fileName/page", () -> done.registration(Medium.TOKEN, null, null));
            return;
        }
        String sid = "00000000-0000-4000-8000-000000000001";
        String obo = done.claimedRole() == null ? null : "NTRMN-1234567";
        assertEquals(name, Medium.TOKEN, done.registration(null, obo).medium());
        assertEquals(name, Medium.PHONE, done.registration(sid, obo).medium());
        expectRequestInvalid(name + ": phone without session", () -> done.registration(Medium.PHONE, null, obo));
        expectRequestInvalid(name + ": token with session", () -> done.registration(Medium.TOKEN, sid, obo));
        if (done.claimedRole() != null) expectRequestInvalid(name + ": claimedRole without onBehalfOf", () -> done.registration(sid, null));
        Registration r = done.registration(Medium.PHONE, sid, obo);
        assertEquals(name, done.docId(), r.docID());
        assertEquals(name, done.revIndex(), r.revIndex());
        assertEquals(name, done.fileName(), r.fileName());
        assertEquals(name, Text.base64(done.cmsRaw()), r.cms());
        assertEquals(name, done.revIndex() == 1 ? done.pageSha256() : null, r.pageSha256());
        assertEquals(name, done.priorCmsSha256().isEmpty() ? null : done.priorCmsSha256(), r.priorCmsSha256());
        assertNull(name, r.priorRevisionSha256());
        List<String> revs = new ArrayList<>();
        for (Registration.PriorSignature ps : r.priorSignatures()) revs.add(ps.revisionSha256());
        assertEquals(name, done.priorRevisionSha256(), revs);
        assertEquals(name, "PNOMN-00000000000", r.signerEtsi());
        Json.Obj json = (Json.Obj) Json.parse(r.toJson().getBytes(StandardCharsets.UTF_8));
        Set<String> want = new LinkedHashSet<>(Arrays.asList("docID", "revIndex", "medium", "sessionID", "cms", "fileName", "inSha256",
            "sigRevSha256", "outSha256", "signerEtsi"));
        want.add(done.revIndex() == 1 ? "pageSha256" : "priorCmsSha256");
        if (obo != null) want.add("onBehalfOf");
        assertEquals(name, want, json.keySet());
        assertEquals(name, "phone", json.getString("medium"));
        assertEquals(name, done.fileName(), json.getString("fileName"));
        if (!done.priorCmsSha256().isEmpty()) {
            Registration all = r.withPriorByRevision(r.priorSignatures().size());
            assertNull(name, all.priorCmsSha256());
            assertEquals(name, done.priorRevisionSha256(), all.priorRevisionSha256());
        }
    }

    @Test
    public void wireExamples() {
        // WIRE.md §1 example request.
        byte[] req = Tsa.request(Cms.sha256("example signature bytes".getBytes(StandardCharsets.US_ASCII)), new BigInteger("9817c2613697bd4d", 16));
        assertEquals("3044020101303130" + "0d060960864801650304020105000420"
            + "9a68ee19b28bcddef1da4964977ae0a070eafb5ccfcbb300b03d4fb9f1ebbfd6" + "0209009817c2613697bd4d0101ff", Text.hex(req));
        // WIRE.md §2 example (golden citizen, issuer 04).
        assertEquals("30433041303f303d303b300906052b0e03021a0500" + "041466d7a67d8f5b73eb50670437691b40eaf94c3b86"
            + "04141722dd2dafa7e06b2a74a1c92a1d0ba6da740df9" + "020203ed", Text.hex(Ocsp.request(Cert.parse(citizen), Cert.parse(chain.get(0)))));
    }

    /** State round trip and Go field order. */
    @Test
    public void stateLayout() {
        byte[] pdf = Golden.file("input/quartz-pdf13.pdf");
        Prepared p = EidPades.prepare(pdf, PrepareOptions.builder(citizen).chain(chain).verifyPage(true).fileName("a.pdf")
            .docId("6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f").build());
        byte[] s = p.state();
        assertEquals("EIDPADES1", new String(s, 0, 9, StandardCharsets.US_ASCII));
        String head = new String(s, 13, 64, StandardCharsets.UTF_8);
        assertTrue(head, head.startsWith("{\"docId\":\"6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f\",\"signerCert\":\""));
        PrepState st = PrepState.decode(s);
        assertEquals("a.pdf", st.fileName);
        assertEquals(1, st.revIndex);
        assertTrue(st.hasPage);
    }
}
