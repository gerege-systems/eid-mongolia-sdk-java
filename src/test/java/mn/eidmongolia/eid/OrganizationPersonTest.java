package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Instant;
import org.junit.Test;

/**
 * OrganizationService and PersonService against the fake RP-API (ports of Go client_test.go TestOrganization,
 * x509_gaps_test.go TestRepresentationsRaw, portal_gaps_test.go TestPersonService / TestRoleLabel /
 * TestRightTypeSourceLabel, share_test.go TestPersonCertificateRevocationFields / TestPersonCertificateTokenSerial,
 * seal_grant_test.go TestOrganization_SealGrants; TS organization/person tests).
 */
public class OrganizationPersonTest {

    // Go TestOrganization + TestRoleLabel + TestRightTypeSourceLabel
    @Test
    public void representations() {
        FakeRp rp = FakeRp.reply(200, "{\"personEtsi\":\"PNOMN-1\",\"representations\":[{\"orgEtsi\":\"NTRMN-6235972\","
            + "\"orgRegister\":\"6235972\",\"orgName\":\"Гэрэгэ\",\"orgNameEn\":\"Gerege\",\"role\":\"ceo\",\"roleLabel\":\"Гүйцэтгэх захирал\","
            + "\"rightType\":\"ADMIN\",\"rightTypeLabel\":\"Админ\",\"source\":\"REGISTRY\",\"sourceLabel\":\"Улсын бүртгэл\","
            + "\"claimedRole\":\"Гүйцэтгэх захирал, Гэрэгэ (NTRMN-6235972)\",\"validFrom\":\"2026-01-01\",\"newField\":1}]}");
        RepresentationsResponse r = rp.builder().language("mn").build().organization().getRepresentations("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/organization/representations/etsi/PNOMN-1");
        assertEquals("mn", rp.last().headers().get("Accept-Language"));
        assertEquals(1, r.representations().size());
        Representation x = r.representations().get(0);
        assertEquals("NTRMN-6235972", x.orgEtsi());
        assertEquals("Гүйцэтгэх захирал", x.roleLabel());
        assertEquals("Админ", x.rightTypeLabel());
        assertEquals("Улсын бүртгэл", x.sourceLabel());
        assertEquals("Гүйцэтгэх захирал, Гэрэгэ (NTRMN-6235972)", x.claimedRole());
        assertEquals("", x.validTo());
        assertTrue("raw keeps unknown members", r.rawJson().contains("newField"));
    }

    // Go TestRepresentationsRaw: empty answer → the requested ETSI and an empty (non-null) list; the path is escaped
    @Test
    public void representationsEmptyAndEscaped() {
        FakeRp rp = FakeRp.reply(200, "");
        RepresentationsResponse r = rp.client().organization().getRepresentations("PNOMN-1/2");
        assertEquals("PNOMN-1/2", r.personEtsi());
        assertTrue(r.representations().isEmpty());
        assertEquals("/organization/representations/etsi/PNOMN-1%2F2", FakeRp.path(rp.last()));
        // 403 (not signed in within 24 h) stays a Forbidden
        FakeRp f = FakeRp.reply(403, "{\"error\":\"24 цагт нэвтрээгүй\",\"code\":\"REPRESENTATION_DENIED\"}");
        try {
            f.client().organization().getRepresentations("PNOMN-1");
            fail();
        } catch (EidException.Forbidden e) {
            assertEquals("REPRESENTATION_DENIED", e.code());
        }
    }

    // Go seal_grant_test.go TestOrganization_SealGrants
    @Test
    public void sealGrants() {
        FakeRp rp = FakeRp.reply(200, "{\"personEtsi\":\"PNOMN-1\",\"organizations\":[{\"orgEtsi\":\"NTRMN-1\",\"orgName\":\"X\","
            + "\"orgStatus\":\"ACTIVE\",\"grants\":[{\"grantId\":\"g1\",\"rpName\":\"Банк\",\"status\":\"APPROVED\",\"createdAt\":\"2026-11-20T01:00:00Z\","
            + "\"decidedAt\":\"2026-11-20T01:02:00Z\",\"approverName\":\"Бат\",\"sealCount\":7,\"sealCount30d\":0,\"lastSealedAt\":\"2026-11-21T00:00:00Z\"},"
            + "{\"grantId\":\"g2\",\"rpName\":\"Банк\",\"status\":\"PENDING\",\"createdAt\":\"2026-11-20T01:00:00Z\",\"expiresAt\":\"2026-11-20T01:10:00Z\"}]},"
            + "{\"orgEtsi\":\"NTRMN-2\",\"orgName\":\"Y\",\"orgStatus\":\"SUSPENDED\"}]}");
        OrgSealGrantsResponse r = rp.client().organization().sealGrants("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/organization/seal-grants/etsi/PNOMN-1");
        assertEquals(2, r.organizations().size());
        OrgSealGrant g = r.organizations().get(0).grants().get(0);
        assertEquals(Long.valueOf(7), g.sealCount());
        assertEquals(Long.valueOf(0), g.sealCount30d());
        assertEquals(Instant.parse("2026-11-21T00:00:00Z"), g.lastSealedAt());
        OrgSealGrant p = r.organizations().get(0).grants().get(1);
        assertNull("unknown statistics stay null, not 0", p.sealCount());
        assertEquals(Instant.parse("2026-11-20T01:10:00Z"), p.expiresAt());
        assertTrue("grants never null", r.organizations().get(1).grants().isEmpty());

        RepresentationsResponse none = FakeRp.reply(200, "{}").client().organization().getRepresentations("PNOMN-9");
        assertEquals("PNOMN-9", none.personEtsi());
        OrgSealGrantsResponse empty = FakeRp.reply(200, "{}").client().organization().sealGrants("PNOMN-9");
        assertEquals("PNOMN-9", empty.personEtsi());
        assertTrue(empty.organizations().isEmpty());
    }

    // Go portal_gaps_test.go TestPersonService
    @Test
    public void personService() {
        FakeRp rp = new FakeRp(q -> {
            String p = FakeRp.path(q);
            if (p.startsWith("/certificates/")) {
                return FakeRp.json(200, "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"valid\":1,\"total\":1},\"certificates\":[{\"documentNumber\":\"d\","
                    + "\"type\":\"AUTH\",\"keyMedium\":\"TOKEN\",\"serialNumber\":\"ab\",\"certificateLevel\":\"ADVANCED\",\"status\":\"VALID\","
                    + "\"notBefore\":\"2026-10-12T16:36:35+08:00\",\"notAfter\":\"2027-10-12T16:36:35+08:00\",\"issuerDn\":\"CN=x\","
                    + "\"organization\":{\"etsi\":\"NTRMN-6235972\",\"name\":\"Гэрэгэ\"},\"tokenSerial\":\"EP2003-0042A1\"},"
                    + "{\"documentNumber\":\"e\",\"type\":\"SIGN\",\"status\":\"SUSPENDED\",\"revokedAt\":\"2026-10-20T00:00:00Z\","
                    + "\"revocationReason\":\"superseded\",\"notBefore\":\"2026-10-12T16:36:35+08:00\",\"notAfter\":\"2027-10-12T16:36:35+08:00\"}]}");
            }
            if (p.startsWith("/devices/")) {
                return FakeRp.json(200, "{\"personEtsi\":\"PNOMN-1\",\"devices\":[{\"documentNumber\":\"d\",\"platform\":\"APNS\","
                    + "\"enrolledAt\":\"2026-10-01T00:00:00Z\",\"active\":true}],\"activeCount\":1,\"total\":1}");
            }
            if (p.startsWith("/rp/activity/")) {
                return FakeRp.json(200, "{\"personEtsi\":\"PNOMN-1\",\"counts\":{\"authentication\":2,\"signature\":1},\"sessions\":[{\"id\":\"9\","
                    + "\"kind\":\"AUTH\",\"flow\":\"AUTHENTICATION\",\"outcome\":\"OK\",\"timestamp\":\"2026-10-01T00:00:00Z\"}],\"total\":3,\"limit\":5,\"offset\":10}");
            }
            if (p.startsWith("/person/summary/")) {
                return FakeRp.json(200, "{\"personEtsi\":\"PNOMN-1\",\"firstName\":\"Бат\",\"lastName\":\"Дорж\",\"nationality\":\"MNG\","
                    + "\"certificates\":{\"valid\":2},\"activity\":{\"authentication\":42},\"devicesActive\":1,\"devicesTotal\":2,\"representationCount\":1}");
            }
            return FakeRp.json(200, "{\"children\":[{\"etsi\":\"PNOMN-2\",\"regNo\":\"УБ\",\"name\":\"Дорж Сүх\",\"registered\":false}]}");
        });
        PersonService ps = rp.client().person();
        PersonCertificates certs = ps.certificates("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/certificates/etsi/PNOMN-1");
        assertEquals(1, certs.counts().valid());
        assertEquals("NTRMN-6235972", certs.certificates().get(0).organization().etsi());
        assertEquals(Instant.parse("2027-10-12T08:36:35Z"), certs.certificates().get(0).notAfter());
        assertEquals("EP2003-0042A1", certs.certificates().get(0).tokenSerial());
        assertNull(certs.certificates().get(0).revokedAt());
        assertEquals("superseded", certs.certificates().get(1).revocationReason()); // Go TestPersonCertificateRevocationFields
        assertEquals(Instant.parse("2026-10-20T00:00:00Z"), certs.certificates().get(1).revokedAt());
        assertNull("no organization → null", certs.certificates().get(1).organization());
        assertFalse(certs.rawJson().isEmpty());

        PersonDevices dev = ps.devices("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/devices/etsi/PNOMN-1");
        assertEquals(1, dev.activeCount());
        assertEquals("APNS", dev.devices().get(0).platform());
        assertTrue(dev.devices().get(0).active());

        PersonActivity act = ps.activity("PNOMN-1", new ActivityQuery("AUTHENTICATION", 5, 10));
        assertEquals("/rp/activity/etsi/PNOMN-1", FakeRp.path(rp.last()));
        assertEquals("flow=AUTHENTICATION&limit=5&offset=10", rp.last().uri().getRawQuery());
        assertEquals(2, act.counts().authentication());
        assertEquals("AUTH", act.sessions().get(0).kind());
        assertEquals(10, act.offset());
        ps.activity("PNOMN-1", null);
        assertNull(rp.last().uri().getRawQuery());
        ps.activity("PNOMN-1", new ActivityQuery("", 0, 0));
        assertNull("zero values send nothing", rp.last().uri().getRawQuery());

        PersonSummary sum = ps.summary("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/person/summary/etsi/PNOMN-1");
        assertEquals("Дорж", sum.lastName());
        assertEquals("MNG", sum.nationality());
        assertEquals(42, sum.activity().authentication());
        assertEquals(1, sum.representationCount());

        PersonChildren ch = ps.children("PNOMN-1");
        FakeRp.assertRequest(rp.last(), "GET", "/person/children/etsi/PNOMN-1");
        assertEquals("Дорж Сүх", ch.children().get(0).name());
        assertNull(ch.children().get(0).certNotAfter());

        try {
            FakeRp.reply(403, "{\"error\":\"RP-д PKI_READ эрх алга\"}").client().person().summary("PNOMN-1");
            fail();
        } catch (EidException.Forbidden expected) {
            // ok
        }
        try {
            FakeRp.reply(404, "{\"error\":\"олдсонгүй\"}").client().person().certificates("PNOMN-1");
            fail();
        } catch (EidException.Api e) {
            assertEquals(404, e.status());
        }
        // A present timestamp that is not RFC 3339 fails like Go time.Time unmarshalling.
        try {
            FakeRp.reply(200, "{\"devices\":[{\"enrolledAt\":\"yesterday\"}]}").client().person().devices("PNOMN-1");
            fail();
        } catch (EidException e) {
            assertTrue(e.getMessage().contains("enrolledAt"));
        }
    }
}
