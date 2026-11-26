package mn.eidmongolia.eid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.Test;

/** Port of Go crypto_test.go / certchoice_callback_test.go and the TS sdk / sign-gaps vectors. */
public class CryptoTest {
    /**
     * Smart-ID RP-API v3 docs (signature_protocols.html) official vector — the CA server (acsp_test.go), iOS, Android,
     * TS and Go SDKs all produce THIS digest.
     */
    static final AcspV2Params SMART_ID = new AcspV2Params(null,
        "MTlop6EXCrQ6FOErcKjxUhbV",
        "GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==",
        "GnsWXXEjTCKR89fj9uo5u5ReBZ9JR7_pezLAI5jMS00",
        "DEMO",
        "Example RP",
        "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d",
        "confirmationMessage",
        "https://rp.example.com/callback-url?value=RrKjjT4aggzu27YBddX1bQ",
        "Web2App");

    @Test
    public void acspV2SmartIdVector() {
        String want = "pKOjbNl/5Fy8NfrFqsj6pSn8W8O+Ik8rM33QSsbyD3J9qDJvEm90SboUciuY4wHGWa0Pnq8BgT3NJKmJiUDfKg==";
        assertEquals(want, Base64.getEncoder().encodeToString(Acsp.v2Digest(SMART_ID, HashAlgorithm.SHA_512)));
        assertEquals(want, Base64.getEncoder().encodeToString(Acsp.v2Digest(SMART_ID, "SHA-512")));
        AcspV2Params p = new AcspV2Params("", SMART_ID.serverRandom(), SMART_ID.rpChallenge(), SMART_ID.userChallenge(),
            SMART_ID.relyingPartyName(), "", SMART_ID.interactions(), SMART_ID.interactionTypeUsed(), "", SMART_ID.flowType());
        String s = new String(Acsp.buildV2Payload(p), StandardCharsets.UTF_8);
        assertTrue("хоосон талбарын тусгаарлагч алдагдав: " + s, s.startsWith("smart-id|ACSP_V2|MTlop6EXCrQ6FOErcKjxUhbV|")
            && s.contains("|REVNTw==||") && s.endsWith("|confirmationMessage||Web2App"));
        try {
            Acsp.v2Digest(SMART_ID, "MD5");
            fail("MD5 зөвшөөрөгдөв");
        } catch (EidException.Validation expected) {
            // ok
        }
    }

    private static String decoded(String b64) {
        return new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
    }

    @Test
    public void interactionsSmartIdVector() {
        String got = EidCrypto.interactionsToBase64(List.of(
            Interaction.confirmationMessage("Longer description of the transaction context"),
            Interaction.displayTextAndPin("Short description of the transaction context")));
        assertEquals(SMART_ID.interactions(), got);
        // JSON.stringify: no HTML escaping, Cyrillic raw UTF-8.
        assertEquals("[{\"type\":\"displayTextAndPIN\",\"displayText60\":\"Банк <А&Б>\"}]",
            decoded(EidCrypto.interactionsToBase64(List.of(Interaction.displayTextAndPin("Банк <А&Б>")))));
        assertEquals("[]", decoded(EidCrypto.interactionsToBase64(null)));
        assertEquals("[]", decoded(EidCrypto.interactionsToBase64(List.of())));
        // Go omitempty: an empty text is omitted.
        assertEquals("[{\"type\":\"x\"}]", decoded(EidCrypto.interactionsToBase64(List.of(new Interaction("x", "", null)))));
    }

    @Test
    public void interactionsLineSeparators() {
        // Go TestInteractionsToBase64_LineSeparators: U+2028/2029 raw, «\» → «\\».
        String got = decoded(EidCrypto.interactionsToBase64(List.of(new Interaction("x", "a\u2028b\u2029c \\u2028 \\\u2028", null))));
        assertEquals("[{\"type\":\"x\",\"displayText60\":\"a\u2028b\u2029c \\\\u2028 \\\\\u2028\"}]", got);
    }

    @Test
    public void interactionsControlAndQuotes() {
        // As JSON.stringify: short escapes for quote, backspace, form feed, newline, CR, tab; other controls as lower-case
        // hex escapes; DEL and the slash raw.
        String got = decoded(EidCrypto.interactionsToBase64(List.of(new Interaction("t", "\"\b\f\n\r\t\u0001\u001f\u007f/", null))));
        assertEquals("[{\"type\":\"t\",\"displayText60\":\"\\\"\\b\\f\\n\\r\\t\\u0001\\u001f\u007f/\"}]", got);
    }

    @Test
    public void interactionsSurrogates() {
        // Paired surrogates (emoji) raw UTF-8; lone surrogates escaped (well-formed JSON.stringify, ES2019).
        String got = decoded(EidCrypto.interactionsToBase64(List.of(new Interaction("t", "\uD83D\uDE00 \uD800 \uDC00", null))));
        assertEquals("[{\"type\":\"t\",\"displayText60\":\"\uD83D\uDE00 \\ud800 \\udc00\"}]", got);
        assertArrayEquals(new byte[] {(byte) 0xF0, (byte) 0x9F, (byte) 0x98, (byte) 0x80}, EidCrypto.utf8("\uD83D\uDE00"));
        assertArrayEquals(new byte[] {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD}, EidCrypto.utf8("\uD800"));
    }

    @Test
    public void sha256AndChallenge() {
        assertEquals("ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=", EidCrypto.sha256Base64("abc".getBytes(StandardCharsets.UTF_8)));
        String c = EidCrypto.randomChallenge(0);
        assertEquals(64, Base64.getDecoder().decode(c).length);
        assertEquals(32, Base64.getDecoder().decode(EidCrypto.randomChallenge(32)).length);
        assertNotEquals("challenge давтагдав", c, EidCrypto.randomChallenge(0));
    }

    @Test
    public void sessionSecretDigest() {
        // TS sign-gaps.test.ts / Go certchoice_callback_test.go.
        String secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        String dg = "Yw3NKWbEM2aRElRIu7JbT_QSpJxzLbLIq8G4WBvXEN0";
        assertEquals(dg, EidCrypto.sessionSecretDigest(secret));
        assertEquals(dg, EidCrypto.sessionSecretDigest("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"));
        assertTrue(EidCrypto.verifySessionSecretDigest(dg, secret));
        assertFalse(EidCrypto.verifySessionSecretDigest(dg.substring(0, dg.length() - 1) + "1", secret));
        assertFalse(EidCrypto.verifySessionSecretDigest(dg, "AAECAw=="));
        assertFalse(EidCrypto.verifySessionSecretDigest("", secret));
        assertFalse(EidCrypto.verifySessionSecretDigest("***", secret));
        assertFalse(EidCrypto.verifySessionSecretDigest(dg + "=", secret));
        assertFalse(EidCrypto.verifySessionSecretDigest(dg, ""));
        assertFalse(EidCrypto.verifySessionSecretDigest(dg, "***"));
        try {
            EidCrypto.sessionSecretDigest("***");
            fail();
        } catch (EidException.DeviceLink expected) {
            // ok
        }
    }

    @Test
    public void userChallengeOf() {
        String verifier = "dGVzdC12ZXJpZmllci0zMi1ieXRlcy14eHh4eHh4eHg";
        String uc = EidCrypto.userChallengeOf(verifier);
        assertTrue(uc.matches("[A-Za-z0-9_-]{43}"));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(
            EidCrypto.digest("SHA-256", verifier.getBytes(StandardCharsets.US_ASCII))), uc);
    }
}
