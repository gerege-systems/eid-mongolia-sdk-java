package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyPair;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import mn.eidmongolia.eid.internal.Cert;
import org.junit.Test;

/**
 * The purely-stricter cross-SDK hardening (not in Go / TS): the RP OCSP checker verifies leaf ← issuer before any
 * network call and binds CertID by default; a subject with more than one SERIALNUMBER / CN is rejected
 * ({@link ValidationReasons#SUBJECT_DUPLICATE_IDENTITY}). All 17 rp-conformance OCSP cases stay green with both
 * (ConformanceTest#ocsp runs the default builder).
 */
public class HardeningTest {

    static Json.Obj ocspCase(String name) {
        for (Object o : ConformanceTest.json("ocsp/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals(name)) return c;
        }
        throw new AssertionError(name);
    }

    @Test
    public void ocspWrongIssuerNeverReachesTheNetwork() {
        Json.Obj good = ocspCase("good");
        List<EidHttpRequest> seen = new ArrayList<>();
        OcspRevocationChecker check = OcspRevocationChecker.builder().transport(ConformanceTest.replay(good.optObj("http"), seen))
            .clock(Clock.fixed(Instant.parse(good.optString("now")), ZoneOffset.UTC)).build();
        java.security.cert.X509Certificate leaf = ConformanceTest.cert(ConformanceTest.bytes(good.optString("certificate")));
        java.security.cert.X509Certificate other = ConformanceTest.cert(ConformanceTest.bytes("pki/05-other.pem"));
        try {
            check.check(leaf, other);
            fail();
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.NO_ISSUER, e.kind());
        }
        try {
            check.check(leaf, leaf);
            fail("the leaf as its own issuer");
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.NO_ISSUER, e.kind());
        }
        assertTrue("no OCSP request for a wrong issuer", seen.isEmpty());
        // the right issuer still answers GOOD (bindCertId on by default)
        java.security.cert.X509Certificate issuer = ConformanceTest.cert(ConformanceTest.bytes(good.optString("issuer")));
        assertEquals(RevocationStatus.GOOD, check.check(leaf, issuer));
        assertEquals(1, seen.size());
    }

    @Test
    public void subjectWithTwoSerialNumbersOrCnsIsRejected() {
        KeyPair k = TestCerts.ec();
        String[][][] subjects = {
            {{"2.5.4.5", "PNOMN-1"}, {"2.5.4.5", "PNOMN-2"}, {"2.5.4.3", "A"}},
            {{"2.5.4.5", "PNOMN-1"}, {"2.5.4.3", "A"}, {"2.5.4.3", "B"}},
        };
        for (String[][] subj : subjects) {
            TestCerts.Spec s = new TestCerts.Spec();
            for (String[] a : subj) s.attr(a[0], a[1]);
            s.key = k;
            s.ku = TestCerts.KU_DIGITAL_SIGNATURE;
            Cert c = Cert.parse(TestCerts.cert(s));
            try {
                ResponseValidator.checkSubject(c);
                fail();
            } catch (EidException.Validation e) {
                assertEquals(ValidationReasons.SUBJECT_DUPLICATE_IDENTITY, e.reason());
                assertTrue("no PII in the message", !e.getMessage().contains("PNOMN-"));
            }
        }
        TestCerts.Spec one = new TestCerts.Spec().attr("2.5.4.5", "PNOMN-1").cn("A");
        one.key = k;
        ResponseValidator.checkSubject(Cert.parse(TestCerts.cert(one)));
    }

    // Review: a path parameter that is empty, "." or ".." is never sent (it would change the route); revIndex is checked
    // against the CA's 1…16 bound before any request.
    @Test
    public void pathParametersAndRevIndexBound() {
        for (String bad : new String[] {"", ".", "..", null}) {
            try {
                Routes.SESSION.expand(bad);
                fail(String.valueOf(bad));
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals("/session/..x", Routes.SESSION.expand("..x"));
        assertEquals("/session/a%2F..", Routes.SESSION.expand("a/.."));
        FakeRp rp = FakeRp.reply(200, "{}");
        EidClient c = rp.client();
        Runnable[] calls = {
            () -> c.session().poll("..", java.time.Duration.ofSeconds(1)),
            () -> c.person().certificates("."),
            () -> c.seal().certificate(""),
            () -> c.pdf().registerSignature(PdfServiceTest.reg(17, mn.eidmongolia.eid.pades.Medium.TOKEN, null, null, null, null, null)),
            () -> c.seal().seal("NTRMN-1234567", new byte[32], HashAlgorithm.SHA_256, "6f0c2b9e-3a1d-4c55-9b7e-0a1b2c3d4e5f", 17),
        };
        for (Runnable r : calls) {
            try {
                r.run();
                fail("accepted");
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
        assertEquals("nothing was sent", 0, rp.seen.size());
    }
}
