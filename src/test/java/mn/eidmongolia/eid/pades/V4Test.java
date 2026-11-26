package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.zip.Deflater;
import mn.eidmongolia.eid.internal.Asn1Time;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * Golden v4 (Go reference v0.8.0): revocation-evidence matching/freshness and revoked = hard error in complete's OCSP/CRL
 * collection (golden/validate/dss-*.pdf), PRECHECKS #2a/#2b structure checks and #4 direct /Encrypt.
 */
public class V4Test {
    private final Json.Obj m = Golden.manifest();
    private final byte[] citizen = Golden.pem("pki/citizen.pem");
    private final List<byte[]> chainDer = Arrays.asList(Golden.pem("pki/04.pem"), Golden.pem("pki/03.pem"), Golden.pem("pki/02.pem"));
    private final byte[] root = Golden.pem("pki/root.pem");

    private static boolean failsStructure(byte[] doc) {
        try {
            Structure.check(doc);
            return false;
        } catch (Structure.Failure e) {
            return true;
        }
    }

    private static byte[] cat(byte[]... parts) {
        return Der.concat(parts);
    }

    // PRECHECKS #2a / #2b / #4

    @Test
    public void deepNestingRejected() {
        PrepareOptions o = PrepareOptions.builder(citizen).chain(chainDer).verifyPage(true).fileName("x.pdf").build();
        for (String name : new String[] {"deep-nesting", "deep-nesting-objstm"}) {
            byte[] doc = Golden.file("validate/" + name + ".pdf");
            assertTrue(name, failsStructure(doc));
            assertEquals(name, "PDF_INVALID", ErrorTest.code(() -> EidPades.prepare(doc, o)));
        }
        for (Object c : m.getArr("cases")) {
            String input = ((Json.Obj) c).getString("input");
            if (!input.startsWith("case:")) assertFalse(input, failsStructure(Golden.file(input)));
        }
        assertFalse(failsStructure(nested(256)));
        assertTrue(failsStructure(nested(257)));
        // The same depth inside a FlateDecode object stream.
        byte[] inner = Golden.ascii("1 0 " + "[".repeat(300) + "]".repeat(300));
        byte[] z = deflate(inner);
        byte[] doc = cat(Golden.ascii("%PDF-1.5\n2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length " + z.length + " >>\nstream\n"),
            z, Golden.ascii("\nendstream\nendobj\n"));
        assertTrue(failsStructure(doc));
        // Go 2026-11-04: a non-integer offset reads from /First; chained filters fail closed.
        byte[] deep = Golden.ascii("1 x " + "[".repeat(300) + "]".repeat(300));
        byte[] doc2 = cat(Golden.ascii("%PDF-1.5\n2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length " + deep.length + " >>\nstream\n"),
            deep, Golden.ascii("\nendstream\nendobj\n"));
        assertTrue(failsStructure(doc2));
        byte[] doc3 = cat(Golden.ascii("%PDF-1.5\n2 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter [/FlateDecode /FlateDecode] /Length "
            + z.length + " >>\nstream\n"), z, Golden.ascii("\nendstream\nendobj\n"));
        assertTrue(failsStructure(doc3));
    }

    private static byte[] nested(int n) {
        return Golden.ascii("%PDF-1.4\n1 0 obj\n<< /X " + "[".repeat(n - 1) + "]".repeat(n - 1) + " >>\nendobj\n");
    }

    private static byte[] deflate(byte[] in) {
        Deflater d = new Deflater();
        d.setInput(in);
        d.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        while (!d.finished()) out.write(buf, 0, d.deflate(buf));
        d.end();
        return out.toByteArray();
    }

    private static byte[] row(int t, int f2, int f3) {
        return new byte[] {(byte) t, (byte) (f2 >> 8), (byte) f2, (byte) f3};
    }

    /** Go `xrefStreamPDF`: obj 1 Catalog (/X 3 0 R), obj 2 xref stream, obj 3 = object 0 of ObjStm 4, obj 4 ObjStm. */
    private static byte[] xrefStreamPdf(String size, String length4, byte[] row3, byte[] row4) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        b.writeBytes(Golden.ascii("%PDF-1.5\n%" + "x".repeat(300) + "\n"));
        int off1 = b.size();
        b.writeBytes(Golden.ascii("1 0 obj\n<< /Type /Catalog /X 3 0 R >>\nendobj\n"));
        int off4 = b.size();
        b.writeBytes(Golden.ascii("4 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length " + length4 + " >>\nstream\n3 0 << >>\nendstream\nendobj\n"));
        int off2 = b.size();
        byte[] rows = cat(row(0, 0, 0xff), row(1, off1, 0), row(1, off2, 0), row3 != null ? row3 : row(2, 4, 0), row4 != null ? row4 : row(1, off4, 0));
        b.writeBytes(Golden.ascii("2 0 obj\n<< /Type /XRef /Size " + size + " /W [1 2 1] /Index [0 5] /Root 1 0 R /Length " + rows.length + " >>\nstream\n"));
        b.writeBytes(rows);
        b.writeBytes(Golden.ascii("\nendstream\nendobj\nstartxref\n" + off2 + "\n%%EOF\n"));
        return b.toByteArray();
    }

    @Test
    public void objStmGraph() {
        byte[] inStm3 = {2, 0, 3, 0};
        Object[][] cases = {
            {"legitimate ObjStm", xrefStreamPdf("5", "9", null, null), false},
            {"/Size = max", xrefStreamPdf(Long.toString(Structure.MAX_XREF_SIZE), "9", null, null), false},
            {"obj 3 is its own container", xrefStreamPdf("5", "9", inStm3, null), true},
            {"ObjStm 4 inside ObjStm 3 (mutual)", xrefStreamPdf("5", "9", null, inStm3), true},
            {"ObjStm /Length inside its own ObjStm", xrefStreamPdf("5", "3 0 R", null, null), true},
            {"/Size 10^10", xrefStreamPdf("10000000000", "9", null, null), true},
        };
        for (Object[] c : cases) {
            String name = (String) c[0];
            byte[] doc = (byte[]) c[1];
            boolean bad = (Boolean) c[2];
            assertEquals(name, bad, failsStructure(doc));
            if (!bad) assertNotNull(name, PdfReader.open(doc).obj(new PdfRef(3, 0)).dict());
        }
    }

    @Test
    public void encryptScan() {
        Object[][] cases = {
            {"/Encrypt 5 0 R", true}, {"/Encrypt<</V 5>>", true}, {"/Encrypt\n<<", true},
            {"/EncryptMetadata false", false}, {"/Encrypt 5 R", false}, {"/Encrypt5 0 R", false},
        };
        for (Object[] c : cases) assertEquals((String) c[0], c[1], Structure.hasEncryptRef(Golden.ascii((String) c[0])));
        // A document the reader cannot open but with a direct /Encrypt dictionary → PDF_ENCRYPTED (#4), not PDF_INVALID.
        byte[] doc = Golden.ascii("%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R /Encrypt << /Filter /Standard /V 5 >> >>\n");
        assertEquals("PDF_ENCRYPTED", ErrorTest.code(() -> EidPades.prepare(doc, PrepareOptions.builder(citizen).chain(chainDer).build())));
        assertEquals("PDF_ENCRYPTED", ErrorTest.code(() -> EidPades.prepare(Golden.file("input/encrypted.pdf"),
            PrepareOptions.builder(citizen).chain(chainDer).build())));
    }

    // Revocation evidence (complete's OCSP/CRL collection)

    /** The final Catalog's /DSS {OCSPs, CRLs}. */
    private static List<List<byte[]>> dss(String name) {
        PdfReader r = PdfReader.open(Golden.file("validate/" + name + ".pdf"));
        PdfDict rootD = r.get(r.trailer, "Root").dict();
        PdfDict d = r.get(rootD, "DSS").dict();
        List<List<byte[]>> out = new ArrayList<>();
        for (String k : new String[] {"OCSPs", "CRLs"}) {
            List<byte[]> l = new ArrayList<>();
            PdfObj a = r.get(d, k);
            if (a instanceof PdfObj.Arr) for (PdfObj it : ((PdfObj.Arr) a).items()) l.add(r.decodedStream(r.resolve(it)));
            out.add(l);
        }
        return out;
    }

    private static List<BigInteger> ocspSerials(byte[] der) {
        List<BigInteger> out = new ArrayList<>();
        try {
            List<Der.Tlv> basic = Der.parse(Der.parse(der).child(1).child(0).child(1).value()).children();
            List<Der.Tlv> rd = basic.get(0).children();
            int i = (rd.get(0).tag == Der.ctx(0) ? 1 : 0) + 2;
            for (Der.Tlv s : rd.get(i).children()) out.add(s.child(0).child(3).bigInt());
        } catch (Exception e) {
            return Collections.emptyList();
        }
        return out;
    }

    /** Serves the DSS evidence as the responders would: OCSP by the requested serial, CRL by the CDP owner's issuer. */
    private static EidPadesTransport dssTransport(List<byte[]> ocsps, List<byte[]> crls, List<Cert> chain) {
        return (method, url, ct, body) -> {
            if (method.equals("POST")) {
                BigInteger serial = Der.parse(body).child(0).child(0).child(0).child(0).child(3).bigInt();
                for (byte[] o : ocsps) if (ocspSerials(o).contains(serial)) return o;
                throw new IOException("404");
            }
            Cert owner = null;
            for (Cert c : chain) {
                if (c.crlDistributionPoints().contains(url)) {
                    owner = c;
                    break;
                }
            }
            if (owner == null) throw new IOException("404");
            for (byte[] der : crls) {
                Crl.Parsed p = Crl.parse(der);
                if (p != null && Arrays.equals(p.rawIssuer, owner.rawIssuer)) return der;
            }
            for (byte[] der : crls) {
                Crl.Parsed p = Crl.parse(der);
                if (p == null) continue;
                boolean inChain = false;
                for (Cert c : chain) inChain |= Arrays.equals(c.rawIssuer, p.rawIssuer);
                if (!inChain) return der;
            }
            throw new IOException("404");
        };
    }

    @Test
    public void revocationEvidenceV4() {
        List<Cert> chain = new ArrayList<>();
        chain.add(Cert.parse(citizen));
        for (byte[] d : chainDer) chain.add(Cert.parse(d));
        List<Cert> roots = Collections.singletonList(Cert.parse(root));
        Date now = Golden.time("2026-10-14T04:00:30Z"); // validate manifest `time`
        String[][] cases = {
            {"dss-ocsp-stale", "unavailable"}, {"dss-ocsp-expired", "unavailable"}, {"dss-ocsp-future", "unavailable"},
            {"dss-ocsp-other-serial", "unavailable"}, {"dss-ocsp-other-issuer", "unavailable"},
            {"dss-ocsp-revoked", "revoked"}, {"dss-ocsp-revoked-after-signing", "revoked"}, {"dss-crl-revoked", "revoked"},
            {"dss-crl-wrong-issuer", "unavailable"}, {"dss-crl-only", "ok"}, {"dss-no-revocation", "unavailable"},
        };
        for (String[] c : cases) {
            String name = c[0];
            String want = c[1];
            List<List<byte[]>> ev = dss(name);
            Fetcher f = new Fetcher(dssTransport(ev.get(0), ev.get(1), chain));
            try {
                Ltv.collect(f, now, new Date(0), roots, chain);
                assertEquals(name, want, "ok");
            } catch (CertificateRevoked e) {
                assertEquals(name + ": " + e.getMessage(), want, "revoked");
                assertEquals(name, "serial 3ed", e.ref);
            } catch (Exception e) {
                assertEquals(name + ": " + e.getMessage(), want, "unavailable");
                // The citizen is named by serial, never by CN (PII).
                assertTrue(name + ": " + e.getMessage(), e.getMessage().contains("serial 3ed"));
                assertFalse(name + ": " + e.getMessage(), e.getMessage().contains("TESTOV"));
            }
        }
    }

    private Json.Obj goldenCase(String name) {
        for (Object o : m.getArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.getString("name").equals(name)) return c;
        }
        throw new IllegalStateException(name);
    }

    private Object[] complete(Json.Obj c, byte[] input, EidPadesTransport transport) {
        Json.Obj p = c.getObj("prepare");
        PrepareOptions o = PrepareOptions.builder(citizen).chain(chainDer).signingTime(Golden.time(m.getString("signingTime")))
            .reason(p.optNonEmpty("reason")).claimedRole(p.optNonEmpty("claimedRole")).docId(p.optNonEmpty("docId"))
            .verifyPage(p.optBool("verifyPage", false)).fileName(p.optNonEmpty("fileName")).lang(p.optNonEmpty("lang")).build();
        Prepared prep = Pades.prepare(input, o);
        String name = c.getString("name");
        Completed res = Pades.complete(prep.stateRaw(), Text.unhex(c.getObj("expect").getString("signature")),
            CompleteOptions.builder().tsaUrl("http://tsa.pki.test/").roots(Collections.singletonList(root)).transport(transport).build(),
            Golden.env(Golden.time(m.getString("now")), name));
        return new Object[] {res, PrepState.decode(prep.stateRaw())};
    }

    /** complete with a revoked citizen OCSP: LTV_UNAVAILABLE, certificateRevoked, not retryable. */
    @Test
    public void completeRevokedIsFinal() {
        Json.Obj c = goldenCase("quartz-pdf13");
        Cert cert = Cert.parse(citizen);
        byte[] revoked = null;
        for (byte[] o : dss("dss-ocsp-revoked").get(0)) if (ocspSerials(o).contains(cert.serial)) revoked = o;
        assertNotNull(revoked);
        byte[] rv = revoked;
        String ocspUrl = cert.ocspServers().get(0);
        EidPadesTransport replay = Golden.replay(m);
        EidPadesTransport t = (method, url, ct, body) -> method.equals("POST") && url.equals(ocspUrl) ? rv : replay.send(method, url, ct, body);
        try {
            complete(c, Golden.file(c.getString("input")), t);
            fail("revoked certificate completed");
        } catch (EidPadesException.LtvUnavailable e) {
            assertTrue(e.getMessage(), e.certificateRevoked());
            assertFalse(e.retryable());
            assertFalse(e.getMessage(), e.getMessage().contains("TESTOV"));
        }
    }

    private static boolean rejects(Runnable r) {
        try {
            r.run();
            return false;
        } catch (Exception e) {
            return true;
        }
    }

    /** The output self-check accepts the real output and rejects one whose new signature is not what was prepared. */
    @Test
    public void selfCheck() {
        Json.Obj first = goldenCase("quartz-pdf13");
        Completed d1 = (Completed) complete(first, Golden.file(first.getString("input")), Golden.replay(m))[0];
        Object[] r2 = complete(goldenCase("quartz-pdf13-second"), d1.pdfRaw(), Golden.replay(m));
        Completed d2 = (Completed) r2[0];
        PrepState st = (PrepState) r2[1];
        List<String[]> prior = Precheck.selfCheck(d2.pdfRaw(), st.byteRange, d2.cmsRaw(), st.revIndex);
        List<String> pc = new ArrayList<>();
        List<String> pr = new ArrayList<>();
        for (String[] x : prior) {
            pc.add(x[0]);
            pr.add(x[1]);
        }
        assertEquals(d2.priorCmsSha256(), pc);
        assertEquals(d2.priorRevisionSha256(), pr);
        assertTrue(rejects(() -> Precheck.selfCheck(d2.pdfRaw(), st.byteRange, d1.cmsRaw(), st.revIndex)));
        assertTrue(rejects(() -> Precheck.selfCheck(d2.pdfRaw(), st.byteRange, d2.cmsRaw(), 1)));
        byte[] tampered = d2.pdf();
        int at = (int) st.byteRange[1] - 10;
        tampered[at] = (byte) (tampered[at] ^ 1);
        assertTrue(rejects(() -> Precheck.selfCheck(tampered, st.byteRange, d2.cmsRaw(), st.revIndex)));
    }

    /** UTCTime is YYMMDD… (CRL thisUpdate/nextUpdate); GeneralizedTime YYYYMMDD… */
    @Test
    public void asn1Time() {
        assertEquals(Golden.time("2026-10-14T04:00:00Z"), Asn1Time.parse(Der.parse(Der.tlv(Der.UTC_TIME, Golden.ascii("261014040000Z")))));
        assertEquals(Golden.time("1999-12-31T23:59:59Z"), Asn1Time.parse(Der.parse(Der.tlv(Der.UTC_TIME, Golden.ascii("991231235959Z")))));
        assertEquals(Golden.time("2026-10-14T04:00:00Z"), Asn1Time.parse(Der.parse(Der.tlv(Der.GENERALIZED_TIME, Golden.ascii("20261014040000Z")))));
    }

    /** ASN.1 times are Gregorian whatever the JVM default locale (th_TH → Buddhist, ja_JP_JP → Japanese imperial). */
    @Test
    public void asn1TimeIgnoresDefaultLocale() {
        java.util.Locale saved = java.util.Locale.getDefault();
        try {
            for (java.util.Locale l : new java.util.Locale[] {new java.util.Locale("th", "TH"), new java.util.Locale("ja", "JP", "JP"),
                java.util.Locale.forLanguageTag("en-US-u-ca-buddhist")}) {
                java.util.Locale.setDefault(l);
                assertEquals(l.toString(), Golden.time("2026-10-14T04:00:00Z"),
                    Asn1Time.parse(Der.parse(Der.tlv(Der.GENERALIZED_TIME, Golden.ascii("20261014040000Z")))));
                assertEquals(l.toString(), Golden.time("2026-10-14T04:00:00Z"),
                    Asn1Time.parse(Der.parse(Der.tlv(Der.UTC_TIME, Golden.ascii("261014040000Z")))));
            }
        } finally {
            java.util.Locale.setDefault(saved);
        }
    }

    // Chain building (Go CheckSignatureFrom / Verify)

    @Test
    public void issuerMustBeCa() {
        Cert c = Cert.parse(citizen);
        Cert ca04 = Cert.parse(chainDer.get(0));
        assertTrue(ca04.isCa() && ca04.basicConstraintsValid());
        assertTrue(c.issuedBy(ca04));
        assertFalse("an end-entity certificate cannot issue", c.mayIssue(Cert.KU_CERT_SIGN));
        assertFalse(ca04.issuedBy(c));
        List<byte[]> all = new ArrayList<>(chainDer);
        all.add(root);
        for (byte[] der : all) {
            Cert x = Cert.parse(der);
            assertTrue(x.mayIssue(Cert.KU_CERT_SIGN));
            Integer pl = x.maxPathLen();
            if (pl != null) {
                assertTrue(x.allowsPath(pl));
                assertFalse(x.allowsPath(pl + 1));
            }
        }
        assertArrayEquals(ca04.subjectKeyId(), ca04.subjectKeyId());
    }
}
