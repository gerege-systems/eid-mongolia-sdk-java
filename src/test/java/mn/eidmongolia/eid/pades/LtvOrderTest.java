package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.Test;

/**
 * LTV revocation collection order by certificate role (Go `pades-golden-v11`, Kotlin `LtvOrderTest` 1:1): the end entity
 * (first certificate of a chain) asks its OCSP first (full timeout) and then its CRL; a CA certificate fetches its CRL
 * first and sends no OCSP request at all when the CRL is valid (a dead CA responder that accepts the connection and never
 * answers is never contacted), falling back to OCSP only without a valid CRL. Fail-closed, revoked fatal, an interrupted
 * caller ends the collection. The golden replay alone cannot prove this — a missing fixture is just a failed responder —
 * so every request is recorded here. Golden PKI: citizen ← 04 ← 03 ← 02 ← root; OCSP only for citizen and 04.
 */
public class LtvOrderTest {
    private final Json.Obj m = Golden.manifest();
    private final Cert citizen = cert("citizen");
    private final Cert ca04 = cert("04");
    private final Cert ca03 = cert("03");
    private final Cert root = cert("root");
    private final List<Cert> chain = Arrays.asList(citizen, ca04, ca03, cert("02"));
    private final Date now = Golden.time(m.getString("now"));
    private final String citizenOcsp = citizen.ocspServers().get(0);
    private final String ca04Ocsp = ca04.ocspServers().get(0);
    private final String citizenCrl = citizen.crlDistributionPoints().get(0);
    private final String ca04Crl = ca04.crlDistributionPoints().get(0);
    private final EidPadesTransport replay = Golden.replay(m);

    private static Cert cert(String n) {
        return Cert.parse(Golden.pem("pki/" + n + ".pem"));
    }

    /** Per-request behaviour, key "METHOD url". */
    private interface Act {
    }

    private static final Act HANG = new Act() {
    };
    private static final Act FAIL = new Act() {
    };

    private static final class Body implements Act {
        final byte[] b;

        Body(byte[] b) {
            this.b = b;
        }
    }

    private static final class Delay implements Act {
        final long ms;

        Delay(long ms) {
            this.ms = ms;
        }
    }

    private static final class FailAfter implements Act {
        final long ms;

        FailAfter(long ms) {
            this.ms = ms;
        }
    }

    /** golden/http replay with per-request behaviour; records requests; interrupt → InterruptedIOException. */
    private final class Fake implements EidPadesTransport {
        private final Map<String, Act> acts;
        final AtomicInteger inFlight = new AtomicInteger();
        final List<String> requests = Collections.synchronizedList(new ArrayList<>());

        Fake(Map<String, Act> acts) {
            this.acts = acts;
        }

        @Override
        public byte[] send(String method, String url, String contentType, byte[] body) throws IOException {
            String key = method + " " + url;
            requests.add(key);
            inFlight.incrementAndGet();
            try {
                Act a = acts.get(key);
                if (a == HANG) {
                    sleep(120_000);
                    throw new IOException("hang ended");
                } else if (a == FAIL) {
                    throw new IOException("404");
                } else if (a instanceof FailAfter) {
                    sleep(((FailAfter) a).ms);
                    throw new IOException("timed out");
                } else if (a instanceof Body) {
                    return ((Body) a).b;
                } else if (a instanceof Delay) {
                    sleep(((Delay) a).ms);
                }
                return replay.send(method, url, contentType, body);
            } finally {
                inFlight.decrementAndGet();
            }
        }

        private void sleep(long ms) throws InterruptedIOException {
            try {
                Thread.sleep(ms);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new InterruptedIOException("interrupted");
            }
        }
    }

    private DssData collect(EidPadesTransport t) throws IOException {
        return Ltv.collect(new Fetcher(t), now, new Date(0), Collections.singletonList(root), chain);
    }

    private byte[] post(Cert c, Cert issuer) throws IOException {
        return new Fetcher(replay).post(c.ocspServers().get(0), "application/ocsp-request", Ocsp.request(c, issuer));
    }

    private byte[] get(String url) throws IOException {
        return new Fetcher(replay).get(url);
    }

    private static List<String> hex(List<byte[]> l) {
        List<String> out = new ArrayList<>();
        for (byte[] b : l) out.add(Text.hex(b));
        return out;
    }

    /** golden/validate/<name>.pdf /DSS {OCSPs, CRLs}. */
    private static List<List<byte[]>> dss(String name) {
        PdfReader r = PdfReader.open(Golden.file("validate/" + name + ".pdf"));
        PdfDict d = r.get(r.get(r.trailer, "Root").dict(), "DSS").dict();
        List<List<byte[]>> out = new ArrayList<>();
        for (String k : new String[] {"OCSPs", "CRLs"}) {
            List<byte[]> l = new ArrayList<>();
            PdfObj a = r.get(d, k);
            if (a instanceof PdfObj.Arr) for (PdfObj it : ((PdfObj.Arr) a).items()) l.add(r.decodedStream(r.resolve(it)));
            out.add(l);
        }
        return out;
    }

    private static long ms(long since) {
        return (System.nanoTime() - since) / 1_000_000;
    }

    private static List<String> posts(List<String> requests) {
        List<String> out = new ArrayList<>();
        synchronized (requests) {
            for (String r : requests) if (r.startsWith("POST")) out.add(r);
        }
        return out;
    }

    /** Healthy chain: leaf OCSP + every CRL; the CA certificate 04 (valid CRL) never contacts its OCSP responder. */
    @Test
    public void caWithValidCrlSendsNoOcsp() throws IOException {
        Fake t = new Fake(Map.of("POST " + ca04Ocsp, HANG));
        long start = System.nanoTime();
        DssData got = collect(t);
        assertTrue(ms(start) + " ms", ms(start) < 5_000);
        assertFalse(t.requests.toString(), t.requests.contains("POST " + ca04Ocsp));
        assertEquals(Collections.singletonList("POST " + citizenOcsp), posts(t.requests));
        assertEquals(hex(Collections.singletonList(post(citizen, ca04))), hex(got.ocsps));
        assertEquals(4, got.crls.size()); // 04, 03, 02, root CRLs, chain order
        assertEquals(hex(Arrays.asList(get(citizenCrl), get(ca04Crl))), hex(got.crls.subList(0, 2)));
        List<byte[]> raws = new ArrayList<>();
        for (Cert c : chain) raws.add(c.raw);
        assertEquals(hex(raws), hex(got.certs.subList(0, 4)));
        assertEquals(0, t.inFlight.get());
    }

    /** Leaf: OCSP is asked first, then its CRL. */
    @Test
    public void leafAsksOcspFirst() throws IOException {
        Fake t = new Fake(Map.of());
        collect(t);
        assertEquals(Arrays.asList("POST " + citizenOcsp, "GET " + citizenCrl), t.requests.subList(0, 2));
    }

    /** CA certificate without a valid CRL (missing, or not its issuer's) → OCSP fallback, embedded. */
    @Test
    public void caWithoutValidCrlFallsBackToOcsp() throws IOException {
        // golden/http has no OCSP for 04 since v11 (its CRL is used); the validate DSS still carries one.
        byte[] ocsp04 = null;
        for (byte[] o : dss("dss-crl-only").get(0)) {
            try {
                Ocsp.parseForCert(o, ca04, ca03);
                ocsp04 = o;
                break;
            } catch (Exception e) {
                // another certificate's response
            }
        }
        assertNotNull("04 OCSP in dss-crl-only", ocsp04);
        byte[] wrongIssuer = get(citizenCrl); // 04's CRL, not 03's
        for (Act act : Arrays.asList(FAIL, new Body(wrongIssuer))) {
            Fake t = new Fake(Map.of("GET " + ca04Crl, act, "POST " + ca04Ocsp, new Body(ocsp04)));
            DssData got = collect(t);
            assertTrue(t.requests.toString(), t.requests.contains("POST " + ca04Ocsp));
            byte[] want = ocsp04;
            assertTrue(got.ocsps.stream().anyMatch(o -> Arrays.equals(o, want)));
            assertEquals(3, got.crls.size());
        }
        // Neither CRL nor OCSP → fail-closed.
        try {
            collect(new Fake(Map.of("GET " + ca04Crl, FAIL, "POST " + ca04Ocsp, FAIL)));
            fail("CA certificate without revocation data accepted");
        } catch (CertificateRevoked e) {
            fail("not revoked");
        } catch (IOException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("no valid OCSP/CRL for serial 3ec"));
        }
    }

    /** A slow leaf OCSP is awaited and embedded (full timeout), even though its CRL is valid. */
    @Test
    public void slowLeafOcspIsAwaited() throws IOException {
        Fake t = new Fake(Map.of("POST " + citizenOcsp, new Delay(600)));
        long start = System.nanoTime();
        DssData got = collect(t);
        assertTrue(ms(start) + " ms", ms(start) >= 550);
        assertEquals(hex(Collections.singletonList(post(citizen, ca04))), hex(got.ocsps));
    }

    /** A dead leaf OCSP (transport timeout) → its CRL after the timeout; without a CRL either → fail-closed. */
    @Test
    public void deadLeafOcspFallsBackToCrl() throws IOException {
        long start = System.nanoTime();
        DssData got = collect(new Fake(Map.of("POST " + citizenOcsp, new FailAfter(400))));
        assertTrue(ms(start) + " ms", ms(start) >= 350);
        assertTrue(got.ocsps.isEmpty());
        assertEquals(Text.hex(get(citizenCrl)), Text.hex(got.crls.get(0)));
        try {
            collect(new Fake(Map.of("POST " + citizenOcsp, FAIL, "GET " + citizenCrl, FAIL)));
            fail("leaf without revocation data accepted");
        } catch (CertificateRevoked e) {
            fail("not revoked");
        } catch (IOException e) {
            assertTrue(e.getMessage(), e.getMessage().contains("no valid OCSP/CRL for serial 3ed"));
        }
    }

    /** Revoked is fatal from either source: the leaf's CRL lists it (even with a good OCSP), or its OCSP says revoked. */
    @Test
    public void revokedFromEitherSourceIsFatal() throws IOException {
        byte[] revokedCrl = null;
        for (byte[] der : dss("dss-crl-revoked").get(1)) {
            Crl.Parsed p = Crl.parse(der);
            if (p != null && Crl.isFor(p, citizen, ca04) && p.revoked.contains(citizen.serial)) revokedCrl = der;
        }
        byte[] revokedOcsp = null;
        for (byte[] der : dss("dss-ocsp-revoked").get(0)) {
            try {
                if (Ocsp.parseForCert(der, citizen, ca04).status == Ocsp.REVOKED) revokedOcsp = der;
            } catch (Exception e) {
                // another certificate's response
            }
        }
        assertNotNull(revokedCrl);
        assertNotNull(revokedOcsp);
        List<Map<String, Act>> cases = Arrays.asList(Map.of("GET " + citizenCrl, new Body(revokedCrl)),
            Map.of("POST " + citizenOcsp, new Body(revokedOcsp)));
        for (Map<String, Act> acts : cases) {
            try {
                collect(new Fake(acts));
                fail("revoked certificate collected (" + acts.keySet() + ")");
            } catch (CertificateRevoked e) {
                assertEquals("serial 3ed", e.ref);
            }
        }
    }

    @Test
    public void garbageLeafOcspFallsBackToCrl() throws IOException {
        DssData got = collect(new Fake(Map.of("POST " + citizenOcsp, new Body(new byte[] {0x30, 0x03, 0x02, 0x01, 0x00}))));
        assertTrue(got.ocsps.isEmpty());
        assertEquals(4, got.crls.size());
    }

    @Test
    public void callerInterruptIsPropagated() throws InterruptedException {
        Fake t = new Fake(Map.of("POST " + citizenOcsp, HANG));
        AtomicReference<Throwable> err = new AtomicReference<>();
        long start = System.nanoTime();
        Thread worker = new Thread(() -> {
            try {
                collect(t);
            } catch (Throwable e) {
                err.set(e);
            }
        });
        worker.start();
        Thread.sleep(200);
        worker.interrupt();
        worker.join(5_000);
        assertFalse("interrupted collect still running", worker.isAlive());
        assertTrue(ms(start) + " ms", ms(start) < 5_000);
        assertTrue(String.valueOf(err.get()), err.get() instanceof InterruptedIOException);
        assertEquals(0, t.inFlight.get());
    }
}
