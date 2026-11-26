package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import mn.eidmongolia.eid.HashAlgorithm;
import mn.eidmongolia.eid.SealCertificate;
import mn.eidmongolia.eid.SealResult;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * sealPdf(qr) → Completed.sealRegistration() against the CA's POST /seal/{orgEtsi}/registrations rules — ports of Go
 * pades/seal_register_test.go and TS test/pades-seal-register.test.ts. The QR cases replay golden v13
 * {@code seal-qr-visible}, {@code citizen-then-seal-qr} and {@code seal-qr-then-seal-qr} end to end through the PUBLIC
 * {@link SealOptions#qr()} (prepare + seal + complete with the manifest's signature, replayed TSA/OCSP/CRL): the output is
 * byte-identical to the Go reference, the reservation is (docId, revIndex) of the golden case and the registration hashes
 * are the manifest's expect values.
 */
public class SealRegisterGoldenTest {
    static final String ORG = "NTRMN-0000000";
    /** CA dto.SealRegisterRequest members (DisallowUnknownFields). */
    static final Set<String> CA_FIELDS = Set.of("docID", "revIndex", "cms", "fileName", "inSha256", "sigRevSha256", "outSha256",
        "priorCmsSha256", "priorRevisionSha256");

    private final Json.Obj m = Golden.manifest();
    private final byte[] seal = Golden.pem("pki/seal.pem");

    /** A DocumentSealer answering with a fixed signature, recording every call (digest, docId, revIndex). */
    static final class Recorder implements DocumentSealer {
        final byte[] cert;
        final byte[] sig;
        final List<Object[]> calls = new ArrayList<>();

        Recorder(byte[] cert, byte[] sig) {
            this.cert = cert;
            this.sig = sig;
        }

        @Override
        public SealCertificate certificate(String orgEtsi) {
            return new SealCertificate(orgEtsi, cert, "1", "", "", Instant.EPOCH, Instant.EPOCH, "QUALIFIED");
        }

        @Override
        public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash) {
            calls.add(new Object[] {Text.hex(digest), null, 0});
            return new SealResult(orgEtsi, sig, "ecdsa-with-SHA256", cert, "QUALIFIED", Instant.EPOCH, "{}");
        }

        @Override
        public SealResult sealForDocument(String orgEtsi, byte[] digest, String docId, int revIndex) {
            calls.add(new Object[] {Text.hex(digest), docId, revIndex});
            return new SealResult(orgEtsi, sig, "ecdsa-with-SHA256", cert, "QUALIFIED", Instant.EPOCH, "{}");
        }
    }

    private static byte[] input(Json.Obj c) {
        String in = c.getString("input");
        return in.startsWith("case:") ? Golden.output(in.substring(5)) : Golden.file(in);
    }

    /** The golden case's SealOptions through the public API (TS goldenOpts: lang moves into the appearance). */
    private SealOptions.Builder goldenOptions(Json.Obj c) {
        Json.Obj p = c.getObj("prepare");
        Json.Obj ap = p.getObj("appearance");
        String lang = p.optNonEmpty("lang");
        return SealOptions.builder().qr(true).reason(p.optNonEmpty("reason")).docId(p.optNonEmpty("docId"))
            .appearance(new SignatureAppearance(ap.optInt("page", 0), ap.getDouble("x"), ap.getDouble("y"), ap.getDouble("width"),
                ap.getDouble("height"), lang, false))
            .signingTime(Golden.time(m.getString("signingTime"))).chain(Golden.chain()).complete(Golden.completeOptions(m));
    }

    /**
     * The CA's network-free checks (Go caAcceptsSealRegistration): handler (≤ 64 KiB, DisallowUnknownFields),
     * normalizeSealRegister (shape), the file proof hashes, SHA-256(signedAttrs) = the sealed digest, reservation = body.
     */
    private static void caAccepts(String name, SealRegistration reg, Json.Obj e, Object[] call) {
        assertNotNull(name, reg);
        String json = reg.toJson();
        assertTrue(name + " body ≤ 64 KiB", json.getBytes(StandardCharsets.UTF_8).length <= 64 << 10);
        Json.Obj body = (Json.Obj) Json.parse(json.getBytes(StandardCharsets.UTF_8));
        assertTrue(name + " DisallowUnknownFields " + body.keySet(), CA_FIELDS.containsAll(body.keySet()));
        reg.validate();
        assertEquals(name, e.getString("docId"), reg.docID());
        assertEquals(name, e.getInt("revIndex"), reg.revIndex());
        byte[] cms = Base64.getDecoder().decode(reg.cms());
        assertTrue(name, cms.length > 0 && cms.length <= SealRegistration.MAX_CMS_BYTES);
        assertEquals(name + " cms_sha256", e.getString("cmsSha256"), Text.hex(Cms.sha256(cms)));
        assertEquals(name + " inSha256", e.getString("inputSha256"), reg.inSha256());
        assertEquals(name + " outSha256", e.getString("outSha256"), reg.outSha256());
        assertEquals(name + " sigRevSha256", e.getString("sigRevSha256"), reg.sigRevSha256());
        List<String> wantPrior = new ArrayList<>();
        List<Object> pa = e.optArr("priorCmsSha256");
        if (pa != null) for (Object o : pa) wantPrior.add((String) o);
        assertEquals(name + " priorCmsSha256", wantPrior, reg.priorCmsSha256() == null ? List.of() : reg.priorCmsSha256());
        assertNull(name, reg.priorRevisionSha256());
        assertEquals(name + " priorSignatures", e.getInt("revIndex") - 1, reg.priorSignatures().size());
        assertEquals(name + " SHA-256(signedAttrs) = the sealed digest (CA SEAL_NOT_FOUND)", e.getString("dtbs"), call[0]);
        if (call[1] != null) {
            assertEquals(name + " reservation = registration (CA SEAL_DOC_MISMATCH)", reg.docID(), call[1]);
            assertEquals(name, reg.revIndex(), call[2]);
        }
    }

    @Test
    public void qrSealMatchesGoldenAndRegisters() {
        for (String name : new String[] {"seal-qr-visible", "citizen-then-seal-qr", "seal-qr-then-seal-qr"}) {
            Json.Obj c = Golden.caseNamed(m, name);
            Json.Obj e = c.getObj("expect");
            byte[] in = input(c);
            assertEquals(name, e.getString("inputSha256"), Text.hex(Cms.sha256(in)));
            Recorder s = new Recorder(seal, Text.unhex(e.getString("signature")));
            Completed done = EidPades.sealPdf(s, ORG, in, goldenOptions(c).fileName(" Нэхэмжлэх.pdf ").build(),
                Golden.env(Golden.time(m.getString("now")), name));
            assertArrayEquals(name + " = Go output/<case>.pdf", Golden.output(name), done.pdfRaw());
            assertEquals(name, e.getString("outSha256"), done.outSha256());
            assertEquals(name + " one sealForDocument", 1, s.calls.size());
            Object[] call = s.calls.get(0);
            assertEquals(name + " reservation docId", e.getString("docId"), call[1]);
            assertEquals(name + " reservation revIndex", e.getInt("revIndex"), call[2]);
            String marker = "/EIDVerify <</URL (https://ca.eidmongolia.mn/verify/" + e.getString("docId") + "/" + e.getInt("revIndex") + ")>> BDC";
            assertTrue(name + " QR marker", new String(done.pdfRaw(), StandardCharsets.ISO_8859_1).contains(marker));
            SealRegistration reg = done.sealRegistration();
            assertEquals(name, "Нэхэмжлэх.pdf", reg.fileName());
            caAccepts(name, reg, e, call);
            if (!reg.priorSignatures().isEmpty()) {
                boolean[] all = new boolean[reg.priorSignatures().size()];
                java.util.Arrays.fill(all, true);
                SealRegistration byRev = reg.withPriorByRevision(all);
                assertNull(name, byRev.priorCmsSha256());
                assertEquals(name, done.priorRevisionSha256(), byRev.priorRevisionSha256());
                byRev.validate();
            }
        }
    }

    /** Go TestSealPDFRegistrationQRless (golden seal-visible): no reservation, a registration for the generated docId. */
    @Test
    public void qrLessSealRegisters() {
        Json.Obj c = Golden.caseNamed(m, "seal-visible");
        Json.Obj e = c.getObj("expect");
        Recorder s = new Recorder(seal, Text.unhex(e.getString("signature")));
        byte[] in = Golden.file("input/libreoffice-contract.pdf");
        Completed done = EidPades.sealPdf(s, ORG, in, SealOptions.builder().reason("Нэхэмжлэх").signingTime(Golden.time(m.getString("signingTime")))
            .chain(Golden.chain()).complete(Golden.completeOptions(m)).build(), Golden.env(Golden.time(m.getString("now")), "seal-visible"));
        assertEquals(e.getString("outSha256"), done.outSha256());
        assertNull("no reservation without a QR", s.calls.get(0)[1]);
        SealRegistration reg = done.sealRegistration();
        reg.validate();
        assertEquals(done.docId(), reg.docID());
        assertEquals(1, reg.revIndex());
        assertNull(reg.fileName());
        assertNull(reg.priorCmsSha256());
        assertEquals(e.getString("sigRevSha256"), reg.sigRevSha256());
        assertEquals(e.getString("dtbs"), s.calls.get(0)[0]);
        assertTrue("no marker in the QR-less stamp", !new String(done.pdfRaw(), StandardCharsets.ISO_8859_1).contains("/EIDVerify"));
    }

    private static void expectRequestInvalid(String what, Runnable r) {
        try {
            r.run();
            fail(what);
        } catch (EidPadesException.RequestInvalid expected) {
            // ok
        }
    }

    /** Go TestSealPDFRegistrationRejects. */
    @Test
    public void rejects() {
        byte[] in = Golden.file("input/quartz-pdf13.pdf");
        Recorder s = new Recorder(seal, new byte[64]);
        // QR needs a DocumentSealer; QR + invisible; a file name over 120 characters — nothing is sealed.
        Sealer plain = new Sealer() {
            @Override
            public SealCertificate certificate(String orgEtsi) {
                return s.certificate(orgEtsi);
            }

            @Override
            public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash) {
                throw new AssertionError("sealed");
            }
        };
        expectRequestInvalid("QR + plain Sealer", () -> EidPades.sealPdf(plain, ORG, in, SealOptions.builder().qr(true).build()));
        expectRequestInvalid("QR + invisible", () -> EidPades.sealPdf(s, ORG, in, SealOptions.builder().qr(true).invisible(true).build()));
        expectRequestInvalid("fileName", () -> EidPades.sealPdf(s, ORG, in, SealOptions.builder().fileName("а".repeat(121)).build()));
        assertTrue(s.calls.isEmpty());
        // A signed document without a verify page / QR seal stamp (golden seal-visible: the QR-less stamp has no docId) and no
        // SealOptions.docId — the QR seal has no docId: REQUEST_INVALID before any seal / reservation.
        byte[] noDocId = Golden.output("seal-visible");
        expectRequestInvalid("QR without docId", () -> EidPades.sealPdf(s, ORG, noDocId, SealOptions.builder().qr(true)
            .signingTime(Golden.time(m.getString("signingTime"))).chain(Golden.chain()).build()));
        assertTrue(s.calls.isEmpty());
        // A citizen Completed → sealRegistration REQUEST_INVALID (use registration()).
        Json.Obj c = Golden.caseNamed(m, "quartz-pdf13-visible");
        Prepared prep = Pades.prepare(Golden.file(c.getString("input")), Golden.prepareOptions(m, c));
        Completed citizen = Pades.complete(prep.stateRaw(), Text.unhex(c.getObj("expect").getString("signature")), Golden.completeOptions(m),
            Golden.env(Golden.time(m.getString("now")), "quartz-pdf13-visible"));
        expectRequestInvalid("citizen", citizen::sealRegistration);
    }

    /** The default (no qr) output is unchanged: SealOptions without the new members = golden seal-visible's DTBS (v12). */
    @Test
    public void defaultUnchanged() {
        Json.Obj e = Golden.caseNamed(m, "seal-visible").getObj("expect");
        Recorder s = new Recorder(seal, Text.unhex(e.getString("signature")));
        EidPades.sealPdf(s, ORG, Golden.file("input/libreoffice-contract.pdf"), SealOptions.builder().reason("Нэхэмжлэх").qr(false)
            .signingTime(Golden.time(m.getString("signingTime"))).chain(Golden.chain()).complete(Golden.completeOptions(m)).build(),
            Golden.env(Golden.time(m.getString("now")), "seal-visible"));
        assertEquals(e.getString("dtbs"), s.calls.get(0)[0]);
    }
}
