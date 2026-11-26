package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.junit.Test;

/**
 * Auth / Sign / certificate choice beyond the wire vectors: device links from the returned sessions, expiry fallback,
 * input checks before any request. Request bodies and paths are in {@link WireVectorTest}.
 */
public class AuthSignServiceTest {
    /** Go sign_gaps_test.go {@code dlReply}. */
    static final String DL_REPLY = "{\"sessionID\":\"0b8f3f0e-1111-4222-8333-444455556666\",\"sessionToken\":\"tok_abc-123\","
        + "\"sessionSecret\":\"c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LTMyYg==\",\"deviceLinkBase\":\"https://ca.eidmongolia.mn/dl\",\"vc\":\"12345\"}";
    static final String PUSH_REPLY = "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"54321\"}}";

    static FakeRp rp() {
        return new FakeRp(r -> FakeRp.json(200, FakeRp.path(r).contains("device-link") ? DL_REPLY : PUSH_REPLY));
    }

    static String query(String link, String k) {
        for (String p : URI.create(link).getRawQuery().split("&")) if (p.startsWith(k + "=")) return p.substring(k.length() + 1);
        return null;
    }

    // Go sign_gaps_test.go TestSignDeviceLink (links)
    @Test
    public void signDeviceLinkLinks() {
        FakeRp rp = rp();
        EidClient c = rp.client();
        String digest = EidCrypto.sha256Base64(EidCrypto.utf8("гэрээ"));
        List<Interaction> ix = List.of(Interaction.displayTextAndPin("Гэрээнд гарын үсэг зурах"));
        DeviceLinkSession s = c.sign().deviceLinkByEtsi("PNOMN-12345678", digest, ix,
            SignOptions.builder().callbackUrl(" https://rp.example.mn/cb ").build());
        for (DeviceLinkType t : DeviceLinkType.values()) {
            String l = DeviceLink.build(s.linkInput(t, "mon").now(s.receivedAt()).build());
            assertEquals("sign", query(l, "sessionType"));
            assertEquals(t.wireName(), query(l, "deviceLinkType"));
        }
        // linkInput is byte-identical to a hand-built input (Web2App — the callback is part of the authCode)
        String manual = DeviceLink.build(DeviceLinkInput.builder().deviceLinkBase(s.deviceLinkBase()).deviceLinkType(DeviceLinkType.WEB2APP)
            .sessionToken(s.sessionToken()).sessionSecret(s.sessionSecret()).sessionType(DeviceLinkSessionType.SIGN).lang("mon")
            .digest(digest).relyingPartyName(FakeRp.CREDS.rpName()).interactions(s.sign().interactions())
            .initialCallbackUrl("https://rp.example.mn/cb").build());
        assertEquals(manual, DeviceLink.build(s.linkInput(DeviceLinkType.WEB2APP, "mon").build()));
        assertEquals(EidCrypto.interactionsToBase64(ix), s.sign().interactions());
        assertFalse("secret in toString", s.toString().contains(s.sessionSecret()));
    }

    // Go client_test.go TestAuth_RequestBodyAndParse (device link) + the ACSP context → device link
    @Test
    public void authDeviceLinkLinksAndContext() {
        FakeRp rp = rp();
        Instant t0 = rp.clock.instant();
        DeviceLinkSession d = rp.client().auth().deviceLinkAnonymous(null, AuthOptions.builder().callbackUrl("https://rp.example.mn/cb").build());
        assertEquals(t0, d.receivedAt());
        assertEquals(DeviceLinkSessionType.AUTH, d.sessionType());
        assertEquals(List.of(FlowType.QR, FlowType.APP2APP, FlowType.WEB2APP), d.acsp().flowTypes());
        assertEquals(d.rpChallenge(), d.acsp().rpChallenge());
        assertEquals("64-byte challenge", 64, Base64.getDecoder().decode(d.rpChallenge()).length);
        Json.Obj body = rp.lastJson();
        assertEquals(d.rpChallenge(), body.optObj("signatureProtocolParameters").optString("rpChallenge"));
        String qr = DeviceLink.build(d.linkInput(DeviceLinkType.QR, "eng").now(t0.plusSeconds(3)).build());
        assertEquals("3", query(qr, "elapsedSeconds"));
        assertEquals("auth", query(qr, "sessionType"));
        DeviceLink.build(d.linkInput(DeviceLinkType.APP2APP, "eng").build());
        // a new challenge per session
        assertNotEquals(d.rpChallenge(), rp.client().auth().deviceLinkAnonymous(null, null).rpChallenge());
    }

    // Go sign_gaps_test.go TestCertificateChoice + certchoice_callback_test.go TestCertChoiceLinkInput_Callback
    @Test
    public void certificateChoiceLinks() {
        FakeRp rp = rp();
        EidClient c = rp.client();
        String cb = "https://rp.example.mn/auth/eid/callback?value=abc";
        DeviceLinkSession with = c.sign().certificateChoiceDeviceLink(CertChoiceOptions.builder().callbackUrl(cb).build());
        for (DeviceLinkType t : new DeviceLinkType[] {DeviceLinkType.WEB2APP, DeviceLinkType.APP2APP}) {
            String l = DeviceLink.build(with.linkInput(t, "mon").build());
            assertEquals("cert", query(l, "sessionType"));
            assertEquals(t.wireName(), query(l, "deviceLinkType"));
        }
        DeviceLinkSession without = c.sign().certificateChoiceDeviceLink(null);
        assertEquals(DeviceLinkSessionType.CERT, without.sessionType());
        assertEquals(FakeRp.CREDS.rpName(), without.relyingPartyName());
        try {
            DeviceLink.build(without.linkInput(DeviceLinkType.WEB2APP, "mon").build());
            fail("no callback → no Web2App");
        } catch (EidException.DeviceLink expected) {
            // ok
        }
        // QR: the authCode does not depend on the callback
        Instant now = with.receivedAt().plusSeconds(3);
        String a = DeviceLink.build(with.linkInput(DeviceLinkType.QR, "mon").now(now).build());
        String b = DeviceLink.build(without.linkInput(DeviceLinkType.QR, "mon").receivedAt(with.receivedAt()).now(now).build());
        assertEquals(a, b);
        assertFalse(a.contains("callback"));
    }

    // Go session_start_test.go TestSessionStartExpiresAtFallback
    @Test
    public void expiresAtFallback() {
        FakeRp rp = new FakeRp(r -> FakeRp.json(200, FakeRp.path(r).contains("device-link")
            ? DL_REPLY : "{\"sessionID\":\"s1\",\"vc\":{\"type\":\"alphaNumeric5\",\"value\":\"54321\"},\"expiresAt\":\"маргааш\"}"));
        Instant t0 = rp.clock.instant();
        NotificationSession n = rp.client().sign().digestByEtsi("PNOMN-1", EidCrypto.sha256Base64(new byte[0]), null, null);
        assertEquals("computed", t0.plus(EidClient.DEFAULT_SIGN_SESSION_TTL), n.expiresAt());
        assertNull("auth without the field → null", rp.client().auth().deviceLinkAnonymous(null, null).expiresAt());
        assertNull("auth with an unparseable value → null", rp.client().auth().notificationByEtsi("PNOMN-1", null, null).expiresAt());
        // Go TestSignExpiresAt: Config.SignSessionTTL follows the CA admin setting
        FakeRp rp2 = rp();
        NotificationSession cc = rp2.builder().signSessionTtl(Duration.ofSeconds(90)).build().sign().certificateChoiceByEtsi("PNOMN-1", null);
        assertEquals(rp2.clock.instant().plusSeconds(90), cc.expiresAt());
    }

    // Go sign_gaps_test.go TestDigestForSigner (bad input → no request)
    @Test
    public void digestForSignerRejectsBeforeRequest() {
        FakeRp rp = rp();
        EidClient c = rp.client();
        String d = EidCrypto.sha256Base64(EidCrypto.utf8("signedAttrs"));
        SignerRef sg = new SignerRef("PNOMN-12345678-ABCD-Q", "cc-1");
        Object[][] cases = {
            {null, d, null},
            {new SignerRef("", null), d, null},
            {new SignerRef(" ", "cc-1"), d, null},
            {sg, Base64.getEncoder().encodeToString(new byte[48]), null}, // 48 bytes for SHA-256
            {sg, d, SignOptions.builder().hashAlgorithm(HashAlgorithm.SHA_512).build()}, // 32 bytes for SHA-512
            {sg, "not base64!", null},
            {sg, d.substring(0, d.length() - 1), null}, // unpadded
            {sg, null, null},
        };
        for (Object[] tc : cases) {
            for (boolean device : new boolean[] {false, true}) {
                try {
                    if (device) c.sign().deviceLinkForSigner((SignerRef) tc[0], (String) tc[1], null, (SignOptions) tc[2]);
                    else c.sign().digestForSigner((SignerRef) tc[0], (String) tc[1], null, (SignOptions) tc[2]);
                    fail("алдаа хүлээв: " + tc[0] + " " + tc[1]);
                } catch (IllegalArgumentException expected) {
                    // ok
                }
            }
        }
        assertEquals("буруу оролтод хүсэлт явав", 0, rp.seen.size());
        // SHA-384 / SHA-512 digests of the right length pass
        c.sign().digestForSigner(sg, Base64.getEncoder().encodeToString(new byte[64]), null,
            SignOptions.builder().hashAlgorithm(HashAlgorithm.SHA_512).build());
        assertEquals("SHA-512", rp.lastJson().optObj("signatureProtocolParameters").optObj("signatureAlgorithmParameters").optString("hashAlgorithm"));
        assertTrue(rp.lastBody().contains("\"linkedSessionID\":\"cc-1\""));
    }

    // Go client_test.go TestAuth_RequestBodyAndParse: the ACSP context carries exactly what was sent
    @Test
    public void authContextMatchesRequest() {
        FakeRp rp = rp();
        List<Interaction> ix = List.of(Interaction.displayTextAndPin("Нэвтрэх <&>  "));
        NotificationSession s = rp.client().auth().notificationByEtsi("PNOMN-12345678", ix,
            AuthOptions.builder().hashAlgorithm(HashAlgorithm.SHA_384).build());
        Json.Obj b = rp.lastJson();
        assertEquals(s.acsp().interactions(), b.optString("interactions"));
        assertEquals(EidCrypto.interactionsToBase64(ix), s.acsp().interactions());
        assertEquals("SHA-384", s.acsp().hashAlgorithm().wireName());
        assertEquals("", s.acsp().brokeredRpName());
        assertEquals(List.of(FlowType.NOTIFICATION), s.acsp().flowTypes());
        assertFalse("no callback → absent", b.has("initialCallbackUrl"));
        assertFalse("no onBehalfOf → absent", b.has("onBehalfOf"));
        assertEquals(FakeRp.CREDS.rpName(), b.optString("relyingPartyName"));
        // the client default certificate level
        rp.builder().defaultCertificateLevel(CertificateLevel.ADVANCED).build().auth().notificationByDocument("D", null, null);
        assertEquals("ADVANCED", rp.lastJson().optString("certificateLevel"));
    }
}
