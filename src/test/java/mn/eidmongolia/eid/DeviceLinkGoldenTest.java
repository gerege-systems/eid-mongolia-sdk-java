package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.Test;

/**
 * Device link v3 + authCode against the CA's frozen vectors: src/test/resources/devicelink_golden.json is an UNEDITED
 * copy of ca-eidmongolia-mn server/internal/crypto/testdata/devicelink_golden.json (byte-identical to the TS SDK
 * test/fixtures and the Go SDK testdata copies; SHA-256 pinned below like Go devicelink_test.go). Port of Go
 * devicelink_test.go.
 */
public class DeviceLinkGoldenTest {
    /** sha256 of the canonical CA file. When the CA updates the vectors, copy the file unedited and update this. */
    static final String DEVICELINK_GOLDEN_SHA256 = "56eb99061af2059d7604c2eb0b8b5d178dd4b789cbfc5db30b03aca99f26a716";

    static final Instant RECEIVED_AT = Instant.ofEpochMilli(1_790_000_000_123L);

    static Json.Obj golden() {
        return (Json.Obj) Json.parse(TestRes.resource("devicelink_golden.json"));
    }

    static Json.Obj vector(Json.Obj g, String name) {
        for (Object o : g.optArr("vectors")) {
            Json.Obj v = (Json.Obj) o;
            if (v.optString("name").equals(name)) return v;
        }
        throw new IllegalStateException("golden вектор алга: " + name);
    }

    static DeviceLinkInput input(Json.Obj g, String name, Duration extra) {
        Json.Obj i = vector(g, name).optObj("input");
        DeviceLinkInput.Builder in = DeviceLinkInput.builder()
            .deviceLinkBase(i.optString("deviceLinkBase"))
            .deviceLinkType(linkType(i.optString("deviceLinkType")))
            .sessionToken(i.optString("sessionToken"))
            .sessionSecret(i.optString("sessionSecret"))
            .sessionType(DeviceLinkSessionType.fromWire(i.optString("sessionType")))
            .lang(i.optString("lang"))
            .receivedAt(RECEIVED_AT)
            .relyingPartyName(i.optString("relyingPartyName"))
            .interactions(i.optString("interactions"))
            .initialCallbackUrl(i.optString("initialCallbackUrl"))
            .schemeName(i.optString("schemeName"))
            .brokeredRpName(i.optString("brokeredRpName"));
        long e = i.optLong("elapsedSeconds", 0);
        in.now(RECEIVED_AT.plus(Duration.ofSeconds(e)).plus(extra));
        String c = i.optString("rpChallengeOrDigest");
        switch (i.optString("sessionType")) {
            case "auth": in.rpChallenge(c); break;
            case "sign": in.digest(c); break;
            default: break;
        }
        return in.build();
    }

    static DeviceLinkType linkType(String s) {
        for (DeviceLinkType t : DeviceLinkType.values()) if (t.wireName().equals(s)) return t;
        throw new IllegalStateException(s);
    }

    @Test
    public void goldenPinned() {
        assertEquals("src/test/resources/devicelink_golden.json — CA-ийн canonical-аас засваргүй хуул", DEVICELINK_GOLDEN_SHA256,
            TestRes.hex(EidCrypto.digest("SHA-256", TestRes.resource("devicelink_golden.json"))));
    }

    @Test
    public void golden() {
        Json.Obj g = golden();
        List<Object> vectors = g.optArr("vectors");
        assertEquals(15, vectors.size());
        Set<String> produced = new HashSet<>();
        for (Object o : vectors) {
            Json.Obj v = (Json.Obj) o;
            String name = v.optString("name");
            for (Duration extra : new Duration[] {Duration.ZERO, Duration.ofMillis(999)}) { // floor
                String got = DeviceLink.build(input(g, name, extra));
                assertEquals(name + " (+" + extra + ")", v.optString("deviceLink"), got);
                produced.add(got);
            }
            assertTrue(name, v.optString("deviceLink").endsWith("&authCode=" + v.optString("authCode")));
        }
        List<Object> invalid = g.optArr("invalid");
        assertEquals(10, invalid.size());
        for (Object o : invalid) {
            Json.Obj bad = (Json.Obj) o;
            assertFalse("invalid холбоос гарав: " + bad.optString("name"), produced.contains(bad.optString("link")));
        }
    }

    @Test
    public void callbackOnlyForSameDevice() {
        Json.Obj g = golden();
        DeviceLinkInput qr = input(g, "eid-qr-auth-e0", Duration.ZERO);
        String want = DeviceLink.build(qr);
        assertEquals("QR-д callback authCode-д орсон", want, DeviceLink.build(qr.toBuilder().initialCallbackUrl("").build()));
        DeviceLinkInput w = input(g, "eid-web2app-auth", Duration.ZERO);
        want = DeviceLink.build(w);
        assertNotEquals("Web2App-д callback authCode-д ороогүй", want,
            DeviceLink.build(w.toBuilder().initialCallbackUrl("https://rp.example.mn/other").build()));
    }

    private static String elapsed(String link) {
        int i = link.indexOf("elapsedSeconds=");
        int j = link.indexOf('&', i);
        return link.substring(i + "elapsedSeconds=".length(), j);
    }

    @Test
    public void elapsedFloorAndClockBack() {
        Json.Obj g = golden();
        DeviceLinkInput qr = input(g, "eid-qr-auth-e7", Duration.ZERO);
        assertEquals("7", elapsed(DeviceLink.build(qr.toBuilder().now(RECEIVED_AT.plusMillis(7999)).build())));
        assertEquals("0", elapsed(DeviceLink.build(qr.toBuilder().now(RECEIVED_AT.minusSeconds(3)).build())));
    }

    @Test
    public void invalid() {
        Json.Obj g = golden();
        DeviceLinkInput qr = input(g, "eid-qr-auth-e0", Duration.ZERO);
        DeviceLinkInput w = input(g, "eid-web2app-auth", Duration.ZERO);
        Map<String, DeviceLinkInput> cases = new LinkedHashMap<>();
        cases.put("http base", qr.toBuilder().deviceLinkBase("http://ca.eidmongolia.mn/dl").build());
        cases.put("scheme base", qr.toBuilder().deviceLinkBase("eidmongolia://approve").build());
        cases.put("base query", qr.toBuilder().deviceLinkBase("https://ca.eidmongolia.mn/dl?x=1").build());
        cases.put("base fragment", qr.toBuilder().deviceLinkBase("https://ca.eidmongolia.mn/dl#x").build());
        cases.put("base empty", qr.toBuilder().deviceLinkBase("").build());
        cases.put("type", qr.toBuilder().deviceLinkType(null).build());
        cases.put("sessionType", qr.toBuilder().sessionType(null).build());
        cases.put("token &", qr.toBuilder().sessionToken("abc&vc=1").build());
        cases.put("token empty", qr.toBuilder().sessionToken("").build());
        cases.put("lang 2", qr.toBuilder().lang("mn").build());
        cases.put("lang upper", qr.toBuilder().lang("MON").build());
        cases.put("secret url", qr.toBuilder().sessionSecret("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8").build());
        cases.put("secret empty", qr.toBuilder().sessionSecret("").build());
        cases.put("auth no challenge", qr.toBuilder().rpChallenge("").build());
        cases.put("sign no digest", qr.toBuilder().sessionType(DeviceLinkSessionType.SIGN).rpChallenge("").build());
        cases.put("cert challenge", qr.toBuilder().sessionType(DeviceLinkSessionType.CERT).build());
        cases.put("QR no receivedAt", qr.toBuilder().receivedAt(null).build());
        cases.put("Web2App no callback", w.toBuilder().initialCallbackUrl("").build());
        cases.put("App2App no callback", w.toBuilder().deviceLinkType(DeviceLinkType.APP2APP).initialCallbackUrl("").build());
        for (Map.Entry<String, DeviceLinkInput> c : cases.entrySet()) {
            try {
                DeviceLink.build(c.getValue());
                fail(c.getKey() + ": DeviceLink exception хүлээв");
            } catch (EidException.DeviceLink expected) {
                // ok
            }
        }
    }

    @Test
    public void sessionLinkInput() {
        Json.Obj g = golden();
        Json.Obj i = vector(g, "eid-web2app-auth").optObj("input");
        AcspContext acsp = new AcspContext(i.optString("rpChallengeOrDigest"), i.optString("relyingPartyName"), "",
            i.optString("interactions"), i.optString("initialCallbackUrl"), List.of(FlowType.WEB2APP), SignatureAlgorithm.RSASSA_PSS,
            HashAlgorithm.SHA_512);
        DeviceLinkSession s = new DeviceLinkSession("sid", i.optString("sessionToken"), i.optString("sessionSecret"),
            i.optString("deviceLinkBase"), "12345", acsp.rpChallenge(), acsp, RECEIVED_AT, null, null, null, null, null);
        assertEquals(vector(g, "eid-web2app-auth").optString("deviceLink"),
            DeviceLink.build(s.linkInput(DeviceLinkType.WEB2APP, i.optString("lang")).schemeName(i.optString("schemeName")).build()));
        assertFalse(s.toString().contains(i.optString("sessionSecret")));
    }
}
