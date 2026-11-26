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
 * ({@link ValidationReasons#CERT_SUBJECT_AMBIGUOUS}). All 17 rp-conformance OCSP cases stay green with both
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
                assertEquals(ValidationReasons.CERT_SUBJECT_AMBIGUOUS, e.reason());
                assertTrue("no PII in the message", !e.getMessage().contains("PNOMN-"));
            }
        }
        TestCerts.Spec one = new TestCerts.Spec().attr("2.5.4.5", "PNOMN-1").cn("A");
        one.key = k;
        ResponseValidator.checkSubject(Cert.parse(TestCerts.cert(one)));
    }
}
