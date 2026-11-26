package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import org.junit.Test;

/** Base URL rules (Go client.go ResolveBaseURL / isLoopback) and builder defaults. */
public class BaseUrlTest {
    private static void rejected(String url, String fragment) {
        try {
            EidClient.resolveBaseUrl(url);
            fail(url + " зөвшөөрөгдөв");
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage(), e.getMessage().contains(fragment));
        }
    }

    @Test
    public void accepted() {
        assertEquals(EidClient.DEFAULT_BASE_URL, EidClient.resolveBaseUrl(null));
        assertEquals(EidClient.DEFAULT_BASE_URL, EidClient.resolveBaseUrl("  "));
        assertEquals("https://rp.eidmongolia.mn", EidClient.resolveBaseUrl("https://rp.eidmongolia.mn///"));
        assertEquals("https://rp.example.mn:8443/eid", EidClient.resolveBaseUrl(" https://rp.example.mn:8443/eid/ "));
        assertEquals("http://localhost:8080", EidClient.resolveBaseUrl("http://localhost:8080"));
        assertEquals("http://LOCALHOST", EidClient.resolveBaseUrl("http://LOCALHOST"));
        assertEquals("http://127.0.0.1:9000", EidClient.resolveBaseUrl("http://127.0.0.1:9000"));
        assertEquals("http://127.1.2.3", EidClient.resolveBaseUrl("http://127.1.2.3"));
        assertEquals("http://[::1]:9000", EidClient.resolveBaseUrl("http://[::1]:9000"));
        assertEquals("http://[::ffff:127.0.0.1]", EidClient.resolveBaseUrl("http://[::ffff:127.0.0.1]"));
        // the legacy host with a path is an explicit choice (Go: legacy only when the path is empty)
        assertEquals("https://ca.eidmongolia.mn/v3", EidClient.resolveBaseUrl("https://ca.eidmongolia.mn/v3"));
    }

    @Test
    public void rejectedUrls() {
        rejected("http://rp.eidmongolia.mn", "https байх ёстой");
        rejected("http://10.0.0.1", "https байх ёстой");
        rejected("http://localhost.example.mn", "https байх ёстой");
        rejected("http://127.0.0.01", "https байх ёстой");
        rejected("http://[::2]", "https байх ёстой");
        rejected("http://[fe80::1]", "https байх ёстой");
        rejected("ftp://rp.eidmongolia.mn", "буруу URL");
        rejected("rp.eidmongolia.mn", "буруу URL");
        rejected("https://", "буруу URL");
        rejected("https://user@", "буруу URL");
        rejected("https://rp eidmongolia.mn", "буруу URL");
        rejected("https://ca.eidmongolia.mn", "шилжсэн");
        rejected("https://ca.eidmongolia.mn/", "шилжсэн");
        rejected("https://e-id.mn", "шилжсэн");
        rejected("https://www.e-id.mn", "шилжсэн");
    }

    @Test
    public void loopbackLiteralsOnly() {
        assertTrue(EidClient.isLoopback("localhost"));
        assertTrue(EidClient.isLoopback("127.0.0.1"));
        assertTrue(EidClient.isLoopback("::1"));
        assertFalse(EidClient.isLoopback("127.0.0.256"));
        assertFalse(EidClient.isLoopback("128.0.0.1"));
        assertFalse(EidClient.isLoopback("::"));
        assertFalse(EidClient.isLoopback("rp.eidmongolia.mn"));
        assertFalse(EidClient.isLoopback(""));
    }

    @Test
    public void builderDefaults() {
        Credentials c = new Credentials("rp-uuid", "Гэрээний систем", "rp_sk_test");
        EidClient e = EidClient.builder(c).transport(r -> {
            throw new AssertionError("no call");
        }).build();
        assertEquals(EidClient.DEFAULT_BASE_URL, e.baseUrl());
        assertEquals(Duration.ofSeconds(15), e.timeout());
        assertEquals(Duration.ofSeconds(80), e.pdfTimeout());
        assertEquals(Duration.ofSeconds(600), e.signSessionTtl());
        assertEquals(CertificateLevel.QUALIFIED, e.defaultCertificateLevel());
        assertEquals("", e.language());
        assertEquals("Гэрээний систем", e.rpName());
        assertFalse(c.toString().contains("rp_sk_test"));

        EidClient f = EidClient.builder(c).timeout(Duration.ofSeconds(-1)).pdfTimeout(Duration.ZERO).language(" en ")
            .defaultCertificateLevel(CertificateLevel.QSCD).build();
        assertEquals(Duration.ofSeconds(15), f.timeout());
        assertEquals(Duration.ofSeconds(80), f.pdfTimeout());
        assertEquals("en", f.language());
        assertEquals(CertificateLevel.QSCD, f.defaultCertificateLevel());

        try {
            EidClient.builder(new Credentials("rp-uuid", "x", "")).build();
            fail("хоосон secret");
        } catch (IllegalArgumentException expected) {
            // ok
        }
        try {
            EidClient.builder(c).baseUrl("http://rp.eidmongolia.mn").build();
            fail("http");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void sessionExpiry() {
        java.time.Instant t = java.time.Instant.parse("2026-11-26T00:00:00Z");
        assertEquals(t.plusSeconds(600), EidClient.sessionExpiry(t, null));
        assertEquals(t.plusSeconds(600), EidClient.sessionExpiry(t, Duration.ZERO));
        assertEquals(t.plusSeconds(90), EidClient.sessionExpiry(t, Duration.ofSeconds(90)));
    }
}
