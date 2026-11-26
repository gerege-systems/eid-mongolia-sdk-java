package mn.eidmongolia.eid;

/**
 * The values a signature session's request carried, exactly as sent (Go {@code SignContext}): for validateSign
 * (digest, hash, algorithm) and the device link (digest, relyingPartyName, interactions, initialCallbackUrl). The RP
 * stores it with the session.
 *
 * @param digest the digest sent (standard base64, EXACTLY as sent — it is part of the device link authCode)
 * @param interactions the base64 STRING sent
 */
public record SignContext(String digest, HashAlgorithm hashAlgorithm, SignatureAlgorithm signatureAlgorithm,
    String relyingPartyName, String interactions, String initialCallbackUrl) {
}
