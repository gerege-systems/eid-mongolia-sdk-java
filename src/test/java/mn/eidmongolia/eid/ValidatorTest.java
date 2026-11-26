package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/** The validator's API around the corpus: roots, trust configuration, client wiring, revocation decisions, OCSP cache. */
public class ValidatorTest {
    private static Json.Obj rpCase(String name) {
        for (Object o : ConformanceTest.json("rp-validate/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals(name)) return c;
        }
        throw new IllegalStateException(name);
    }

    private static Json.Obj ocspCase(String name) {
        for (Object o : ConformanceTest.json("ocsp/cases.json").optArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.optString("name").equals(name)) return c;
        }
        throw new IllegalStateException(name);
    }

    private static X509Certificate pki(String name) {
        return ConformanceTest.cert(ConformanceTest.bytes("pki/" + name));
    }

    private static TrustConfig.Builder corpusTrust() {
        Json.Obj tr = ConformanceTest.json("rp-validate/cases.json").optObj("trust").optObj("default");
        List<String> anchors = new ArrayList<>();
        for (Object p : tr.optArr("anchors")) anchors.add(ConformanceTest.pemText((String) p));
        List<String> inter = new ArrayList<>();
        for (Object p : tr.optArr("intermediates")) inter.add(ConformanceTest.pemText((String) p));
        List<String> skis = new ArrayList<>();
        for (Object s : tr.optArr("allowedIssuerSkis")) skis.add((String) s);
        return TrustConfig.builder().trustAnchorsPem(anchors).intermediatesPem(inter).allowedIssuerSkis(skis);
    }

    private static String sha256(String pem) {
        return ConformanceTest.sha256(Cert.pemSingle(pem.getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
    }

    @Test
    public void roots() {
        // Byte-identical to Go roots.go NationalRootCAPEM / CitizenIntermediatesPEM (and TS NATIONAL_ROOT_CA_PEM / CITIZEN_INTERMEDIATES_PEM).
        assertEquals("cbe7f3fe1f048037c215da321e58caa4f363de9e54bbc442a3bfd62fad834482", sha256(Roots.NATIONAL_ROOT_CA_PEM));
        assertEquals(3, Roots.CITIZEN_INTERMEDIATES_PEM.size());
        assertEquals("9423640dd74561d1af1ea8a093860bda7df5b5620bb617921395dc0d1a1f980d", sha256(Roots.CITIZEN_INTERMEDIATES_PEM.get(0)));
        assertEquals("56f3d1ca7f282287619773905aa0cd7a427d4f95dc0ed7b6733963a89bc31237", sha256(Roots.CITIZEN_INTERMEDIATES_PEM.get(1)));
        assertEquals("87b8db6862abde5e4a07a10c2c696afe5cb6aea072b9f3f9755e73ce79f546fc", sha256(Roots.CITIZEN_INTERMEDIATES_PEM.get(2)));
        Cert ca04 = Cert.parse(Cert.pemSingle(Roots.CITIZEN_INTERMEDIATES_PEM.get(2).getBytes(java.nio.charset.StandardCharsets.US_ASCII)));
        assertEquals(Roots.CITIZEN_ISSUING_CA_SKI, Text.hex(ca04.subjectKeyId()));
        // The production trust parses (root + default intermediates).
        assertNotNull(new ResponseValidator(TrustConfig.builder().trustAnchorsPem(Roots.NATIONAL_ROOT_CA_PEM).build()));
    }

    @Test
    public void trustConfigErrors() {
        for (TrustConfig t : List.of(TrustConfig.builder().trustAnchorsPem("not a pem").build(),
            TrustConfig.builder().intermediatesPem(List.of("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")).build(),
            TrustConfig.builder().allowedIssuerSkis(List.of("zz")).build(),
            TrustConfig.builder().allowedIssuerSkis(List.of("abc")).build())) {
            try {
                new ResponseValidator(t);
                fail("accepted");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage(), expected.getMessage().startsWith("eid: "));
            }
        }
        // ":"-separated upper-case SKIs are normalised (Go strings.ToLower + ReplaceAll).
        assertNotNull(new ResponseValidator(TrustConfig.builder().allowedIssuerSkis(List.of(" 68:8D:74:02 ")).build()));
    }

    /** client.validator() uses Builder.trust and the client's clock; without trust it fails closed. */
    @Test
    public void clientValidator() {
        Json.Obj c = rpCase("auth-pss-sha512-qr");
        SessionResult r = SessionService.parseSessionResult(FakeRp.text(c.get("session")));
        AcspContext a = ConformanceTest.acsp(c.optObj("acsp"));
        FakeRp rp = FakeRp.reply(200, "{}");
        VerifiedIdentity id = rp.builder().trust(corpusTrust().build()).build().validator().validateAuth(r, a);
        assertEquals("PNOMN-999999990001-MOCK-Q", id.documentNumber());
        assertEquals(CertificateLevel.QUALIFIED, id.certificateLevel());
        assertEquals(new Subject("TEST", "TESTOV", "TESTOV TEST", "PNOMN-999999990001", "MN"), id.subject());
        try {
            rp.client().validator().validateAuth(r, a);
            fail("no anchor accepted");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.TRUST_NO_ANCHOR, e.reason());
        }
        // allowUntrusted (dev only) skips the chain — but an explicit issuer allowlist is still checked (TS rule).
        assertEquals("PNOMN-999999990001-MOCK-Q", rp.builder().trust(TrustConfig.builder().allowUntrusted(true).build()).build()
            .validator().validateAuth(r, a).documentNumber());
        try {
            rp.builder().trust(TrustConfig.builder().allowUntrusted(true).allowedIssuerSkis(List.of("00")).build()).build()
                .validator().validateAuth(r, a);
            fail("issuer allowlist skipped");
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.ISSUER_NOT_ALLOWED, e.reason());
        }
        try {
            rp.builder().trust(corpusTrust().build()).build().validator().validateAuth(r, null);
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.AUTH_ACSP_MISSING, e.reason());
        }
    }

    @Test
    public void signedCallbackUrl() {
        String cb = "https://rp.example/cb";
        assertEquals(cb, ResponseValidator.signedCallbackUrl(null, cb, "QR"));
        assertEquals("", ResponseValidator.signedCallbackUrl("", cb, "QR"));
        assertEquals(cb, ResponseValidator.signedCallbackUrl(cb, cb, "Web2App"));
        for (String[] bad : new String[][] {{"https://evil/cb", "QR"}, {"", "Web2App"}, {"", "App2App"}}) {
            try {
                ResponseValidator.signedCallbackUrl(bad[0], cb, bad[1]);
                fail(bad[0] + " " + bad[1]);
            } catch (EidException.Validation e) {
                assertEquals(ValidationReasons.AUTH_CALLBACK_URL, e.reason());
            }
        }
    }

    /** Go CheckRevocationWith: the decision table, the issuer from the trust pool, the OCSP no-answer cause kept. */
    @Test
    public void revocationDecisions() {
        ResponseValidator v = new ResponseValidator(corpusTrust().build());
        X509Certificate leaf = pki("leaf-auth.pem");
        AtomicReference<X509Certificate> issuer = new AtomicReference<>();
        RevocationChecker good = (c, i) -> {
            issuer.set(i);
            return RevocationStatus.GOOD;
        };
        assertEquals(RevocationOutcome.GOOD, v.checkRevocationWith(leaf, good, null));
        assertEquals(pki("04-eid.pem"), issuer.get());
        assertEquals(RevocationOutcome.SKIPPED, v.checkRevocationWith(leaf, null, null));
        assertEquals(RevocationOutcome.SKIPPED, v.checkRevocationStatus(leaf));
        v.checkRevocation(leaf); // no checker configured → no-op
        expectReason(() -> v.checkRevocationWith(leaf, (c, i) -> RevocationStatus.REVOKED, RevocationMode.SOFT_FAIL), ValidationReasons.REVOCATION_REVOKED);
        expectReason(() -> v.checkRevocationWith(leaf, (c, i) -> RevocationStatus.UNKNOWN, null), ValidationReasons.REVOCATION_UNKNOWN);
        expectReason(() -> v.checkRevocationWith(leaf, (c, i) -> null, RevocationMode.HARD_FAIL), ValidationReasons.REVOCATION_UNKNOWN);
        assertEquals(RevocationOutcome.UNCHECKED, v.checkRevocationWith(leaf, (c, i) -> RevocationStatus.UNKNOWN, RevocationMode.SOFT_FAIL));
        EidException.Ocsp noAnswer = new EidException.Ocsp(EidException.Ocsp.Kind.TIMEOUT, "http://ocsp.example/", 0, "", null);
        RevocationChecker silent = (c, i) -> {
            throw noAnswer;
        };
        assertEquals(RevocationOutcome.UNCHECKED, v.checkRevocationWith(leaf, silent, RevocationMode.SOFT_FAIL));
        try {
            v.checkRevocationWith(leaf, silent, RevocationMode.HARD_FAIL);
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.REVOCATION_UNKNOWN, e.reason());
            assertSame(noAnswer, e.getCause());
        }
        try {
            v.checkRevocationWith(leaf, (c, i) -> {
                throw new IllegalStateException("boom");
            }, RevocationMode.SOFT_FAIL);
            fail();
        } catch (EidException.Validation e) {
            fail("a checker failure is not a validation result");
        } catch (EidException e) {
            assertTrue(e.getCause() instanceof IllegalStateException);
        }
        // Configured checker + mode.
        ResponseValidator hard = new ResponseValidator(corpusTrust().revocation((c, i) -> RevocationStatus.UNKNOWN).build());
        expectReason(() -> hard.checkRevocation(leaf), ValidationReasons.REVOCATION_UNKNOWN);
        ResponseValidator soft = new ResponseValidator(corpusTrust().revocation((c, i) -> RevocationStatus.UNKNOWN)
            .revocationMode(RevocationMode.SOFT_FAIL).build());
        assertEquals(RevocationOutcome.UNCHECKED, soft.checkRevocationStatus(leaf));
    }

    private static void expectReason(Runnable r, String reason) {
        try {
            r.run();
            fail("accepted, " + reason + " expected");
        } catch (EidException.Validation e) {
            assertEquals(reason, e.reason());
        }
    }

    /** Go NewOCSPChecker cache: GOOD kept min(5 min, nextUpdate); failures and REVOKED never cached; observer told. */
    @Test
    public void ocspCache() {
        Json.Obj good = ocspCase("good");
        Instant now = Instant.parse(good.optString("now"));
        FakeRp.FakeClock clock = new FakeRp.FakeClock(now);
        List<EidHttpRequest> seen = new ArrayList<>();
        List<OcspRevocationChecker.OcspObservation> obs = new ArrayList<>();
        OcspRevocationChecker check = OcspRevocationChecker.builder().transport(ConformanceTest.replay(good.optObj("http"), seen))
            .clock(clock).observer(obs::add).build();
        X509Certificate leaf = pki("leaf-auth.pem");
        X509Certificate ca04 = pki("04-eid.pem");
        assertEquals(RevocationStatus.GOOD, check.check(leaf, ca04));
        assertEquals(1, seen.size());
        clock.advance(Duration.ofMinutes(4));
        assertEquals(RevocationStatus.GOOD, check.check(leaf, ca04));
        assertEquals("cached", 1, seen.size());
        clock.advance(Duration.ofMinutes(2));
        assertEquals(RevocationStatus.GOOD, check.check(leaf, ca04));
        assertEquals("cache expired after 5 min", 2, seen.size());
        assertEquals(3, obs.size());
        assertTrue(obs.get(1).cached());
        assertEquals("http://ocsp.conformance.test/ocsp", obs.get(0).responder());
        assertNull(obs.get(0).error());

        Json.Obj revoked = ocspCase("unknown-is-revoked");
        seen.clear();
        OcspRevocationChecker r = OcspRevocationChecker.builder().transport(ConformanceTest.replay(revoked.optObj("http"), seen))
            .clock(new FakeRp.FakeClock(now)).build();
        assertEquals(RevocationStatus.REVOKED, r.check(leaf, ca04));
        assertEquals(RevocationStatus.REVOKED, r.check(leaf, ca04));
        assertEquals("revoked is not cached", 2, seen.size());

        OcspRevocationChecker none = OcspRevocationChecker.builder().transport(ConformanceTest.replay(null, new ArrayList<>()))
            .clock(new FakeRp.FakeClock(now)).cacheTtl(Duration.ofSeconds(-1)).build();
        try {
            none.check(leaf, null);
            fail();
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.NO_ISSUER, e.kind());
            assertEquals("no_issuer", e.code());
        }
        try {
            none.check(pki("04-eid.pem"), pki("02-national.pem")); // a CA without an AIA OCSP URL
            fail();
        } catch (EidException.Ocsp e) {
            assertEquals(EidException.Ocsp.Kind.NO_RESPONDER, e.kind());
        }
        // Through the validator: no answer + hard-fail → revocation.unknown with the OCSP reason as the cause.
        ResponseValidator v = new ResponseValidator(corpusTrust().revocation(none).build());
        try {
            v.checkRevocation(pki("leaf-auth.pem"));
            fail();
        } catch (EidException.Validation e) {
            assertEquals(ValidationReasons.REVOCATION_UNKNOWN, e.reason());
            assertEquals(EidException.Ocsp.Kind.HTTP_STATUS, ((EidException.Ocsp) e.getCause()).kind());
            assertEquals(404, ((EidException.Ocsp) e.getCause()).httpStatus());
        }
    }

    @Test
    public void subjectParse() {
        X509Certificate leaf = pki("leaf-sign.pem");
        Subject s = Subject.parse(leaf);
        assertEquals("PNOMN-999999990001", s.serialNumber());
        assertEquals("MN", s.country());
        assertEquals(new Subject("", "", "", "", ""), Subject.parse(null));
        assertEquals(CertificateLevel.QUALIFIED, ResponseValidator.certificateLevelOf(leaf, ResponseValidator.PROTOCOL_RAW_DIGEST));
        assertEquals(CertificateLevel.ADVANCED, ResponseValidator.certificateLevelOf(pki("leaf-sign-no-qc.pem"), ResponseValidator.PROTOCOL_RAW_DIGEST));
        assertEquals(CertificateLevel.QSCD, ResponseValidator.certificateLevelOf(pki("leaf-sign-qscd.pem"), ResponseValidator.PROTOCOL_RAW_DIGEST));
        assertEquals(CertificateLevel.QUALIFIED, ResponseValidator.certificateLevelOf(pki("leaf-auth.pem"), ResponseValidator.PROTOCOL_ACSP_V2));
        assertEquals(CertificateLevel.ADVANCED, ResponseValidator.certificateLevelOf(pki("leaf-auth.pem"), ResponseValidator.PROTOCOL_RAW_DIGEST));
        assertEquals(CertificateLevel.QUALIFIED, ResponseValidator.certificateLevelOf(pki("leaf-token-auth-ec.pem"), ResponseValidator.PROTOCOL_ACSP_V2));
        expectReason(() -> ResponseValidator.certificateLevelOf(pki("leaf-sign-qc-malformed.pem"), ResponseValidator.PROTOCOL_RAW_DIGEST),
            ValidationReasons.LEVEL_QC_MALFORMED);
    }
}
