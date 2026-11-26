package mn.eidmongolia.eid;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Crypto helpers — digest, random challenge, interactions, linked-signing callback digest, userChallenge (Go
 * {@code crypto.go}, {@code certchoice.go}, {@code validator.go} {@code UserChallengeOf}; TS {@code crypto.ts}).
 */
public final class EidCrypto {
    private static final SecureRandom RANDOM = new SecureRandom();

    private EidCrypto() {
    }

    /** SHA-256 digest, standard base64 — the document digest of a signature flow. */
    public static String sha256Base64(byte[] data) {
        return Base64.getEncoder().encodeToString(digest("SHA-256", data));
    }

    /** A random RP challenge of {@code n} bytes (n ≤ 0 → 64), standard base64 — protects authentication against replay. */
    public static String randomChallenge(int n) {
        byte[] b = new byte[n <= 0 ? 64 : n];
        RANDOM.nextBytes(b);
        return Base64.getEncoder().encodeToString(b);
    }

    /**
     * The interactions array as the RP-API v3 base64 string: base64(UTF-8(JSON.stringify(interactions))), byte-identical
     * to the TS and Go SDKs (no HTML escaping, U+2028/U+2029 raw; members type, displayText60, displayText200, empty
     * texts omitted as in Go {@code omitempty}). Store THIS string and give it to the validator — never re-serialise.
     */
    public static String interactionsToBase64(List<Interaction> interactions) {
        List<Map<String, Object>> arr = new ArrayList<>();
        if (interactions != null) {
            for (Interaction i : interactions) {
                Map<String, Object> o = new LinkedHashMap<>();
                o.put("type", i.type());
                if (i.displayText60() != null && !i.displayText60().isEmpty()) o.put("displayText60", i.displayText60());
                if (i.displayText200() != null && !i.displayText200().isEmpty()) o.put("displayText200", i.displayText200());
                arr.add(o);
            }
        }
        return Base64.getEncoder().encodeToString(utf8(Json.stringify(arr)));
    }

    /**
     * The linked-signing callback's {@code sessionSecretDigest}: BASE64URL-NOPAD(SHA-256(base64-decode(sessionSecret)))
     * — sessionSecret of the certificate-choice device-link session (standard base64, else base64url, padded or not).
     *
     * @throws EidException.DeviceLink when the input is not base64
     */
    public static String sessionSecretDigest(String sessionSecret) {
        byte[] key = decodeSessionSecret(sessionSecret);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest("SHA-256", key));
    }

    /** Checks the callback's sessionSecretDigest against sessionSecret in constant time; malformed input → false. */
    public static boolean verifySessionSecretDigest(String digest, String sessionSecret) {
        String want;
        try {
            want = sessionSecretDigest(sessionSecret);
        } catch (EidException.DeviceLink e) {
            return false;
        }
        if (digest == null || digest.isEmpty()) return false;
        return MessageDigest.isEqual(digest.getBytes(StandardCharsets.UTF_8), want.getBytes(StandardCharsets.UTF_8));
    }

    /** Smart-ID: userChallenge = BASE64URL-NOPAD(SHA-256(UTF-8(userChallengeVerifier))). */
    public static String userChallengeOf(String verifier) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest("SHA-256", utf8(verifier)));
    }

    /**
     * A signature over an ACSP_V2 payload (Go {@code VerifyPayloadSignature}): HASH_hash(payload) checked by
     * {@link #verifyPrehashedSignature}.
     *
     * @param alg the response's signatureAlgorithm (rsassa-pss, shaNNNWithRSAEncryption, ecdsa-with-SHA256)
     * @param hash "SHA-256" | "SHA-384" | "SHA-512"; anything else → false
     */
    public static boolean verifyPayloadSignature(byte[] payload, String sigB64, java.security.PublicKey pub, String alg, String hash) {
        if (Prehashed.hashLen(hash) == 0 || payload == null) return false;
        return Prehashed.verify(digest(hash, payload), sigB64, pub, alg, hash);
    }

    /**
     * A signature over a ready digest (Go {@code VerifyPrehashedSignature}, TS {@code verifyPrehashedSignature}):
     * rsassa-pss (MGF1 with the same hash, salt = hLen), shaNNNWithRSAEncryption (PKCS#1 v1.5), ecdsa-with-SHA256 (P-256,
     * SHA-256, ASN.1 DER — not IEEE P1363). RSA keys below 2048 bits, a key type that does not fit the algorithm, or a digest whose length is not
     * the hash's → false.
     */
    public static boolean verifyPrehashedSignature(byte[] digest, String sigB64, java.security.PublicKey pub, String alg, String hash) {
        return Prehashed.verify(digest, sigB64, pub, alg, hash);
    }

    /** Go certchoice.go decodeSessionSecret: standard base64, else base64url (padded or not); non-empty. */
    static byte[] decodeSessionSecret(String s) {
        s = s == null ? "" : s.trim();
        if (s.isEmpty()) throw new EidException.DeviceLink("sessionSecret хоосон");
        for (Base64.Decoder d : new Base64.Decoder[] {Base64.getDecoder(), Base64.getUrlDecoder()}) {
            try {
                byte[] b = d.decode(s);
                if (b.length > 0) return b;
            } catch (IllegalArgumentException e) {
                // try the next alphabet
            }
        }
        throw new EidException.DeviceLink("sessionSecret base64 биш");
    }

    /**
     * UTF-8 bytes with a lone surrogate encoded as U+FFFD (EF BF BD) — like Node {@code Buffer.from(s, "utf8")} / JS
     * {@code TextEncoder}; {@link String#getBytes} would write '?' instead.
     */
    static byte[] utf8(String s) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int cp;
            if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                cp = Character.toCodePoint(c, s.charAt(++i));
            } else if (Character.isSurrogate(c)) {
                cp = 0xFFFD;
            } else {
                cp = c;
            }
            if (cp < 0x80) {
                out.write(cp);
            } else if (cp < 0x800) {
                out.write(0xC0 | (cp >> 6));
                out.write(0x80 | (cp & 0x3F));
            } else if (cp < 0x10000) {
                out.write(0xE0 | (cp >> 12));
                out.write(0x80 | ((cp >> 6) & 0x3F));
                out.write(0x80 | (cp & 0x3F));
            } else {
                out.write(0xF0 | (cp >> 18));
                out.write(0x80 | ((cp >> 12) & 0x3F));
                out.write(0x80 | ((cp >> 6) & 0x3F));
                out.write(0x80 | (cp & 0x3F));
            }
        }
        return out.toByteArray();
    }

    static byte[] digest(String alg, byte[] data) {
        try {
            return MessageDigest.getInstance(alg).digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(alg, e);
        }
    }
}
