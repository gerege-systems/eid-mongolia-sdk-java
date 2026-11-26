package mn.eidmongolia.eid.pades.validate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/**
 * Hostile-input regressions for the validator internals (review of PR #13): each test has a hard time bound and would
 * have run for minutes / exhausted the heap (or wrongly accepted) before the fix.
 */
public class ValidateHardeningTest {
    private static final long BOUND_MS = 5_000;

    static byte[] res(String p) {
        try (InputStream s = ValidateHardeningTest.class.getResourceAsStream("/pades-validate/" + p)) {
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] latin1(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static void within(long t0) {
        long ms = (System.nanoTime() - t0) / 1_000_000;
        assertTrue("took " + ms + " ms", ms < BOUND_MS);
    }

    /** "%PDF-1.7\n" + body objects at their offsets + classic xref + trailer. objs[i] = body of object i+1 (no header). */
    static byte[] pdf(List<String> objs, String trailerExtra) {
        StringBuilder b = new StringBuilder("%PDF-1.7\n");
        List<Integer> offs = new ArrayList<>();
        for (int i = 0; i < objs.size(); i++) {
            offs.add(b.length());
            b.append(i + 1).append(" 0 obj\n").append(objs.get(i)).append("\nendobj\n");
        }
        int x = b.length();
        b.append("xref\n0 ").append(objs.size() + 1).append("\n0000000000 65535 f \n");
        for (int o : offs) b.append(String.format("%010d 00000 n \n", o));
        b.append("trailer\n<< /Size ").append(objs.size() + 1).append(" /Root 1 0 R").append(trailerExtra).append(" >>\nstartxref\n").append(x)
            .append("\n%%EOF\n");
        return latin1(b.toString());
    }

    // 1 — a huge digit token

    @Test
    public void hugeDigitTokenIsRejectedFast() {
        String digits = "7".repeat(9_000_000);
        byte[] d = latin1("%PDF-1.7\nxref\n" + digits + " 1\ntrailer\n<<>>\nstartxref\n9\n%%EOF\n");
        long t0 = System.nanoTime();
        try {
            new DReader(d);
            fail("accepted");
        } catch (DReader.PdfError e) {
            within(t0);
        }
    }

    // 2, 3 — overlapping streams sharing one trailing endstream

    /** n stream objects whose data all run to one shared "endstream endobj" after ~filler bytes. */
    private static byte[] overlapping(int n, int filler) {
        StringBuilder head = new StringBuilder("%PDF-1.7\n");
        int[] dataStart = new int[n];
        int[] lenPos = new int[n];
        int[] hdr = new int[n];
        for (int i = 0; i < n; i++) {
            hdr[i] = head.length();
            head.append(i + 1).append(" 0 obj\n<< /Length ");
            lenPos[i] = head.length();
            head.append("0000000000 >>\nstream\n");
            dataStart[i] = head.length();
        }
        int end = head.length() + filler;
        StringBuilder all = new StringBuilder(head);
        all.append(" ".repeat(filler)).append("\nendstream\nendobj\n");
        for (int i = 0; i < n; i++) {
            String l = String.format("%010d", end - dataStart[i]);
            all.replace(lenPos[i], lenPos[i] + 10, l);
        }
        int x = all.length();
        all.append("xref\n0 ").append(n + 1).append("\n0000000000 65535 f \n");
        for (int i = 0; i < n; i++) all.append(String.format("%010d 00000 n \n", hdr[i]));
        all.append("trailer\n<< /Size ").append(n + 1).append(" /Root 1 0 R >>\nstartxref\n").append(x).append("\n%%EOF\n");
        return latin1(all.toString());
    }

    @Test
    public void overlappingUnfilteredStreamsHitTheReaderBudget() {
        byte[] d = overlapping(4096, 8 << 20);
        DReader r = new DReader(d);
        long t0 = System.nanoTime();
        int read = 0;
        try {
            for (int i = 1; i <= 4096; i++) {
                r.resolve(DReader.NO_PTR, new DReader.PRef(i, 0)).streamData();
                read++;
            }
            fail("no budget");
        } catch (DReader.PdfError e) {
            assertTrue("read " + read, read < 64);
            within(t0);
        }
    }

    @Test
    public void overlappingNestedStreamsHitTheParserCopyBudget() {
        byte[] d = overlapping(4096, 8 << 20);
        PdfObjects.PdfBudget budget = new PdfObjects.PdfBudget();
        long t0 = System.nanoTime();
        int parsed = 0;
        try {
            int pos = 9;
            for (int i = 0; i < 4096; i++) {
                PdfParser p = new PdfParser(d, d.length, pos, budget);
                p.indirect(null);
                parsed++;
                pos = indexOf(d, (i + 2) + " 0 obj", pos);
                if (pos < 0) break;
            }
            fail("no budget");
        } catch (PdfObjError e) {
            assertTrue("parsed " + parsed, parsed < 64);
            within(t0);
        }
    }

    @Test
    public void dssItemsOverTheCapAreSkippedBeforeReading() throws Exception {
        // A DSS whose 64 /OCSPs entries are 8 MiB streams: skipped by /Length, nothing copied.
        List<String> objs = new ArrayList<>();
        StringBuilder arr = new StringBuilder("[");
        for (int i = 0; i < 64; i++) arr.append(" 4 0 R");
        objs.add("<< /Type /Catalog /DSS 2 0 R >>");
        objs.add("<< /OCSPs " + arr + " ] /CRLs 3 0 R >>");
        objs.add("[ 4 0 R 4 0 R ]");
        objs.add("<< /Length " + (8 << 20) + " >>\nstream\n" + " ".repeat(8 << 20) + "\nendstream");
        byte[] d = pdf(objs, "");
        DReader r = new DReader(d);
        long t0 = System.nanoTime();
        java.lang.reflect.Method m = Extract.class.getDeclaredMethod("extractDss", DReader.Value.class);
        m.setAccessible(true);
        Extract.RawDss dss = (Extract.RawDss) m.invoke(null, r.trailerValue().key("Root").key("DSS"));
        assertEquals(0, dss.ocsps.size());
        assertEquals(0, dss.crls.size());
        within(t0);
    }

    private static int indexOf(byte[] b, String s, int from) {
        byte[] k = latin1(s);
        outer:
        for (int i = from; i <= b.length - k.length; i++) {
            for (int j = 0; j < k.length; j++) if (b[i + j] != k[j]) continue outer;
            return i;
        }
        return -1;
    }

    // 4 — a huge OID

    @Test
    public void hugeOidIsRejectedFast() {
        byte[] v = new byte[5 << 20];
        java.util.Arrays.fill(v, (byte) 0x81);
        v[v.length - 1] = 0x01;
        long t0 = System.nanoTime();
        try {
            Asn1.oidString(v);
            fail("accepted");
        } catch (Asn1.Error e) {
            within(t0);
        }
        // as a CMS contentType: ContentInfo { OID(5 MiB), [0] {} } — no signature needed to reach it
        byte[] oid = Der.tlv(0x06, v);
        byte[] cms = Der.seq(oid, Der.tlv(0xa0, Der.seq()));
        t0 = System.nanoTime();
        assertNull(Extract.parsePkcs7(cms));
        within(t0);
        assertEquals("1.2.840.113549.1.7.2", Asn1.oidString(new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x07, 0x02}));
    }

    // 5 — xref stream table growth

    private static byte[] xrefStream(String dict, byte[] data) {
        String head = "%PDF-1.7\n%" + "x".repeat(300) + "\n"; // %%EOF search needs a 200-byte window
        String obj = "1 0 obj\n<< /Type /XRef " + dict + " /Length " + data.length + " >>\nstream\n";
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(latin1(head + obj));
        o.writeBytes(data);
        o.writeBytes(latin1("\nendstream\nendobj\nstartxref\n" + head.length() + "\n%%EOF\n"));
        return o.toByteArray();
    }

    @Test
    public void xrefStreamWithEmptyRowsIsRejected() {
        long t0 = System.nanoTime();
        try {
            new DReader(xrefStream("/Size 1 /W [0 0 0] /Index [0 9223372036854775807]", new byte[0]));
            fail("accepted");
        } catch (DReader.PdfError e) {
            within(t0);
        }
    }

    @Test
    public void xrefStreamDoesNotGrowPastTheIdCap() {
        byte[] zeros = new byte[64 << 20];
        Deflater def = new Deflater(9);
        def.setInput(zeros);
        def.finish();
        ByteArrayOutputStream z = new ByteArrayOutputStream();
        byte[] buf = new byte[65536];
        while (!def.finished()) z.write(buf, 0, def.deflate(buf));
        def.end();
        long t0 = System.nanoTime();
        DReader r = new DReader(xrefStream("/Size 1 /W [1 0 0] /Index [0 67108864] /Filter /FlateDecode", z.toByteArray()));
        assertTrue("xref " + r.xref.size(), r.xref.size() <= (1 << 21));
        within(t0);
    }

    // 6 — a 100k-member object stream

    @Test
    public void largeObjectStreamIsIndexedOnce() {
        int n = 100_000;
        StringBuilder hdr = new StringBuilder();
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < n; i++) {
            hdr.append(i + 3).append(' ').append(body.length()).append(' ');
            body.append(i).append(' ');
        }
        String stm = hdr.toString() + body;
        String head = "%PDF-1.7\n";
        StringBuilder s = new StringBuilder(head);
        int o2 = s.length();
        s.append("2 0 obj\n<< /Type /ObjStm /N ").append(n).append(" /First ").append(hdr.length()).append(" /Length ").append(stm.length())
            .append(" >>\nstream\n").append(stm).append("\nendstream\nendobj\n");
        // xref stream: obj 0 free, 1 = this xref stream, 2 = the object stream, 3.. compressed in 2
        ByteArrayOutputStream rows = new ByteArrayOutputStream();
        rows.writeBytes(new byte[] {0, 0, 0, 0, 0, 0});
        int o1 = s.length();
        rows.writeBytes(new byte[] {1, (byte) (o1 >> 24), (byte) (o1 >> 16), (byte) (o1 >> 8), (byte) o1, 0});
        rows.writeBytes(new byte[] {1, (byte) (o2 >> 24), (byte) (o2 >> 16), (byte) (o2 >> 8), (byte) o2, 0});
        for (int i = 0; i < n; i++) rows.writeBytes(new byte[] {2, 0, 0, 0, 2, (byte) Math.min(i, 255)});
        byte[] rb = rows.toByteArray();
        s.append("1 0 obj\n<< /Type /XRef /Size ").append(n + 3).append(" /W [1 4 1] /Root 3 0 R /Length ").append(rb.length).append(" >>\nstream\n");
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(latin1(s.toString()));
        o.writeBytes(rb);
        o.writeBytes(latin1("\nendstream\nendobj\nstartxref\n" + o1 + "\n%%EOF\n"));
        DReader r = new DReader(o.toByteArray());
        long t0 = System.nanoTime();
        for (int i = 0; i < n; i++) assertEquals("int", r.resolve(DReader.NO_PTR, new DReader.PRef(i + 3, 0)).kind());
        within(t0);
    }

    // 7 — the shadow /Length attack

    private static final PadesSupport NO_STAMPS = new PadesSupport() {
        @Override
        public boolean structureOk(byte[] doc) {
            return true;
        }

        @Override
        public List<byte[]> appearanceObjects(int w, int h, int rotate, String name, String role, String lang, String date, String url,
            boolean seal, int[] ids) {
            throw new UnsupportedOperationException();
        }

        @Override
        public byte[] visibleWidget(String fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId) {
            throw new UnsupportedOperationException();
        }
    };

    private static LaterChanges later(byte[] doc) throws Exception {
        Extract.Extracted ex = Extract.extract(doc, NO_STAMPS);
        Extract.RawSignature s = ex.sigs.get(0);
        Map<Integer, long[]> known = new LinkedHashMap<>();
        known.put(s.objNum, s.byteRange);
        Revisions rv = new Revisions(doc, known, "own", NO_STAMPS);
        rv.sigs = ex.metas;
        rv.docID = ex.docId;
        return rv.later(s.signedEnd);
    }

    @Test
    public void streamLengthRunningIntoALaterRevisionIsModifiedAfterSigning() throws Exception {
        byte[] d = res("golden/output/quartz-pdf13.pdf");
        assertTrue("control", later(d).signaturesOnly);
        // In the signed revision: a stream whose /Length now runs past the signed end, up to an "endstream" of the later
        // DSS revision (same byte count: "/Length 7204 >>" → "/Length NNNNN>>").
        long signedEnd = Extract.extract(d, NO_STAMPS).sigs.get(0).signedEnd;
        int at = indexOf(d, "/Length 7204 >>", 100_000);
        assertTrue(at > 0 && at < signedEnd);
        int data = indexOf(d, "stream", at) + 7;
        int target = indexOf(d, "endstream", (int) signedEnd);
        String l = Integer.toString(target - data);
        assertEquals(5, l.length());
        byte[] a = d.clone();
        System.arraycopy(latin1("/Length " + l + ">>"), 0, a, at, 15);
        LaterChanges c = later(a);
        assertFalse("shadow /Length accepted as signatures-only", c.signaturesOnly);
    }

    // 8 — RSA-PSS parameters

    private static Asn1.Node pss(String hashOid, String mgfHashOid, int salt, Integer trailer) {
        List<byte[]> f = new ArrayList<>();
        if (hashOid != null) f.add(Der.tlv(0xa0, Der.seq(Der.oid(hashOid))));
        if (mgfHashOid != null) f.add(Der.tlv(0xa1, Der.seq(Der.oid("1.2.840.113549.1.1.8"), Der.seq(Der.oid(mgfHashOid)))));
        if (salt >= 0) f.add(Der.tlv(0xa2, Der.integer(salt)));
        if (trailer != null) f.add(Der.tlv(0xa3, Der.integer(trailer)));
        return Asn1.parseOne(Der.seq(f.toArray(new byte[0][])));
    }

    @Test
    public void pssParametersAreStrict() {
        assertEquals("SHA-256", VCrypto.pssHash(pss(VCrypto.SHA256, VCrypto.SHA256, 32, null)));
        assertEquals("SHA-512", VCrypto.pssHash(pss(VCrypto.SHA512, VCrypto.SHA512, 64, 1)));
        assertNull("SHA-1 defaults", VCrypto.pssHash(Asn1.parseOne(Der.seq())));
        assertNull("SHA-1", VCrypto.pssHash(pss(VCrypto.SHA1, VCrypto.SHA1, 20, null)));
        assertNull("MGF hash differs", VCrypto.pssHash(pss(VCrypto.SHA256, VCrypto.SHA1, 32, null)));
        assertNull("salt", VCrypto.pssHash(pss(VCrypto.SHA256, VCrypto.SHA256, 20, null)));
        assertNull("trailer", VCrypto.pssHash(pss(VCrypto.SHA256, VCrypto.SHA256, 32, 2)));
        assertNull("no MGF", VCrypto.pssHash(pss(VCrypto.SHA256, null, 32, null)));
        // a chain signature with PSS/SHA-1 parameters never verifies (no exception either)
        Cert root = Cert.parse(Cert.pemSingle(res("golden/pki/root.pem")));
        Asn1.Node alg = Asn1.parseOne(Der.seq(Der.oid(VCrypto.RSA_PSS), Der.seq()));
        assertFalse(VCrypto.verify(root, alg, new byte[] {1}, new byte[256]));
    }

    // 9 — SHA-1 signature algorithm on the SignerInfo

    @Test
    public void sha1SignerAlgorithmIsWeak() throws Exception {
        byte[] d = res("golden/output/quartz-pdf13.pdf");
        Extract.RawSignature s0 = Extract.extract(d, NO_STAMPS).sigs.get(0);
        assertFalse(s0.weakDigest);
        long[] br = s0.byteRange;
        int gs = (int) br[1] + 1;
        int ge = (int) br[2] - 1;
        byte[] contents = Text.unhex(d, gs, ge);
        // SignedData → signerInfos[0] → signatureAlgorithm OID := sha1WithRSAEncryption (same length as rsaEncryption)
        Asn1.Node ci = Asn1.readNode(contents, 0);
        Asn1.Node sd = Asn1.children(Asn1.children(ci).get(1)).get(0);
        List<Asn1.Node> f = Asn1.children(sd);
        Asn1.Node sis = f.get(f.size() - 1);
        List<Asn1.Node> si = Asn1.children(Asn1.children(sis).get(0));
        Asn1.Node enc = null;
        for (int i = 3; i < si.size(); i++) {
            if (si.get(i).tag == Asn1.SEQUENCE) {
                enc = Asn1.children(si.get(i)).get(0);
                break;
            }
        }
        assertNotNull(enc);
        assertTrue(Asn1.oid(enc), Asn1.oid(enc).startsWith("1.2.840.113549.1.1."));
        // sha1WithRSA (.5), md5WithRSA (.4), md2WithRSA (.2) — Go weakSignatureOIDs
        for (byte last : new byte[] {0x05, 0x04, 0x02}) {
            contents[enc.end - 1] = last;
            byte[] a = d.clone();
            byte[] hex = latin1(Text.hex(contents));
            System.arraycopy(hex, 0, a, gs, hex.length);
            Extract.RawSignature s = Extract.extract(a, NO_STAMPS).sigs.get(0);
            assertTrue("1.2.840.113549.1.1." + last, s.weakDigest);
        }
    }

    // 10 — at most 32 certificates per CMS (Go boundedCerts: checked after parsing, the signature is malformed)

    @Test
    public void tooManyEmbeddedCertificatesIsMalformed() {
        byte[] c = Cert.pemSingle(res("golden/pki/root.pem"));
        assertTrue(Extract.boundedCerts(Extract.parsePkcs7(cms(c, 32)).certs));
        long t0 = System.nanoTime();
        assertFalse(Extract.boundedCerts(Extract.parsePkcs7(cms(c, 33)).certs));
        within(t0);
    }

    private static byte[] cms(byte[] cert, int n) {
        byte[][] cs = new byte[n][];
        for (int i = 0; i < n; i++) cs[i] = cert;
        byte[] sd = Der.seq(Der.integer(1), Der.set(), Der.seq(Der.oid("1.2.840.113549.1.7.1")), Der.tlv(0xa0, Der.concat(cs)), Der.set());
        return Der.seq(Der.oid(Extract.O_SIGNED_DATA), Der.tlv(0xa0, sd));
    }

    // 11 — a malformed non-critical extension the validator reads

    @Test
    public void malformedEkuFailsOnlyThatCertificate() {
        byte[] der = Cert.pemSingle(res("golden/pki/tsa.pem"));
        byte[] eku = Text.unhex("0603551d250101ff040c300a06082b06010505070308");
        int at = indexOf(der, new String(eku, StandardCharsets.ISO_8859_1), 0);
        assertTrue(at > 0);
        byte[] bad = der.clone();
        bad[at + 7] = 0x00; // critical FALSE
        bad[at + 11] = 0x0b; // inner SEQUENCE length overruns
        Cert.parse(bad); // the JDK keeps it as an unparseable non-critical extension
        try {
            VCrypto.cert(bad);
            fail("accepted");
        } catch (IllegalArgumentException e) {
            // a per-certificate failure, never PDF_INVALID for the document
        }
    }

    /** An unsigned test certificate (the signature is not checked by the parser) with the given serial and RSA key. */
    private static Cert rsaCert(java.math.BigInteger serial, java.math.BigInteger n, java.math.BigInteger e) {
        byte[] alg = Der.seq(Der.oid("1.2.840.113549.1.1.11"), Der.nullValue());
        byte[] name = Der.seq(Der.set(Der.seq(Der.oid("2.5.4.3"), Der.tlv(0x0c, latin1("TEST ONLY BOUNDS")))));
        byte[] validity = Der.seq(Der.tlv(0x17, latin1("260101000000Z")), Der.tlv(0x17, latin1("310101000000Z")));
        byte[] key = Der.seq(Der.integer(n), Der.integer(e));
        byte[] bits = new byte[key.length + 1];
        System.arraycopy(key, 0, bits, 1, key.length);
        byte[] spki = Der.seq(Der.seq(Der.oid("1.2.840.113549.1.1.1"), Der.nullValue()), Der.tlv(0x03, bits));
        byte[] tbs = Der.seq(Der.tlv(0xa0, Der.integer(2)), Der.integer(serial), alg, name, validity, name, spki);
        return VCrypto.certAnySerial(Der.seq(tbs, alg, Der.tlv(0x03, new byte[257])));
    }

    @Test
    public void oversizedSerialAndRsaKeysAreBounded() {
        java.math.BigInteger one = java.math.BigInteger.ONE;
        java.math.BigInteger n2048 = one.shiftLeft(2047).add(one);
        java.math.BigInteger e = java.math.BigInteger.valueOf(65537);
        java.math.BigInteger s160 = one.shiftLeft(160).subtract(one);
        assertTrue("control", Extract.boundedCerts(List.of(rsaCert(s160, n2048, e))));
        assertTrue("-2^159 = 160 bits", Extract.boundedCerts(List.of(rsaCert(one.shiftLeft(159).negate(), n2048, e))));
        assertFalse("serial 161 bits", Extract.boundedCerts(List.of(rsaCert(one.shiftLeft(160), n2048, e))));
        assertFalse("-2^160 = 161 bits", Extract.boundedCerts(List.of(rsaCert(one.shiftLeft(160).negate(), n2048, e))));
        assertTrue("modulus 8192 bits", Extract.boundedCerts(List.of(rsaCert(one, one.shiftLeft(8191).add(one), e))));
        assertFalse("modulus 8193 bits", Extract.boundedCerts(List.of(rsaCert(one, one.shiftLeft(8192).add(one), e))));
        assertTrue("e = 2^32 - 1", Extract.boundedCerts(List.of(rsaCert(one, n2048, one.shiftLeft(32).subtract(one)))));
        assertFalse("e = 2^32 + 1", Extract.boundedCerts(List.of(rsaCert(one, n2048, one.shiftLeft(32).add(one)))));
        // VCrypto.cert (DSS / chain certificates) keeps rejecting a serial over 160 bits at parse time
        try {
            VCrypto.cert(rsaCert(one.shiftLeft(160), n2048, e).raw);
            fail("accepted");
        } catch (IllegalArgumentException x) {
            // expected
        }
    }

    // 12 — later-signature trust (Go extract.go known/metas): corpus v14 inputs, v15 expectations

    @Test
    public void laterSignatureMustVerifyToExtend() throws Exception {
        byte[] d = res("validate/input/later-sig-integrity-failed.pdf");
        Extract.Extracted ex = Extract.extract(d, NO_STAMPS);
        assertEquals(2, ex.sigs.size());
        int bad = 0;
        for (Extract.RawSignature s : ex.sigs) {
            if (!s.integrity) {
                bad++;
                assertFalse("an unverified signature has no stamp meta", ex.metas.containsKey(s.objNum));
            }
        }
        assertEquals(1, bad);
    }

    // Corpus v15 (Go 9f68390 TestValidatePDFLaterStampNameNotCompared): the stamp's /Name is not compared with the
    // certificate name — a mismatching /Name on an integrity-passing later signature does NOT flag earlier signatures.
    @Test
    public void laterStampNameIsNotCompared() throws Exception {
        ValidatePdfOptions o = ValidatePdfOptions.builder()
            .roots(List.of(Cert.pemSingle(res("golden/pki/root.pem"))))
            .issuers(List.of(Cert.pemSingle(res("golden/pki/04.pem")), Cert.pemSingle(res("validate/pki/05.pem"))))
            .time(java.time.Instant.parse("2026-10-14T04:00:30Z"))
            .offline(true)
            .transport((method, url, ct, body) -> { throw new IOException("offline"); })
            .build();
        // mismatch: the later signature's certificate is QUALIFIED TESTOV, its /Name and stamp say GOLDEN TESTOV.
        String[][] cases = {{"later-stamp-name-mismatch", "GOLDEN TESTOV"}, {"later-stamp-name-control", "QUALIFIED TESTOV"}};
        for (String[] c : cases) {
            PdfReport r = mn.eidmongolia.eid.pades.EidPades.validatePdf(res("validate/input/" + c[0] + ".pdf"), o);
            assertEquals(c[0], 2, r.signatures().size());
            PdfReport.SignatureReport first = r.signatures().get(0), later = r.signatures().get(1);
            if (first.coversWholeDocument()) {
                PdfReport.SignatureReport x = first;
                first = later;
                later = x;
            }
            assertEquals(c[0], "valid", first.indication());
            assertTrue(c[0] + " " + first.problems(), first.problems().isEmpty());
            assertTrue(c[0] + ": extended by signatures only", first.extendedBySignaturesOnly());
            assertTrue(c[0] + ": visible later signature", first.visibleLaterSignature());
            assertEquals(c[0], 1, first.laterSignatures());
            assertEquals(c[0], "QUALIFIED TESTOV", later.signerName());
            assertEquals(c[0], c[1], later.claimedName());
            assertTrue(c[0], later.visible());
        }
    }
}
