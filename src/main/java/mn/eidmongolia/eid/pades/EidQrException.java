package mn.eidmongolia.eid.pades;

/**
 * «Миний QR» error. {@link #code()} is stable (same strings as the Go / TS / .NET SDKs) — branch on it; the message is
 * for logs only.
 */
public final class EidQrException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** The scanned string is not an eID «My QR» (client side). */
    public static final String FORMAT_INVALID = "QR_FORMAT_INVALID";
    /** JWS structure / payload JSON invalid. */
    public static final String JWS_MALFORMED = "QR_JWS_MALFORMED";
    /** Header (alg PS256, typ, x5c of 2 certificates) invalid. */
    public static final String HEADER_INVALID = "QR_HEADER_INVALID";
    /** Chain / leaf profile (QUALIFIED, contentCommitment, issuer SKI, RSA ≥ 2048, validity). */
    public static final String CHAIN_INVALID = "QR_CHAIN_INVALID";
    /** The citizen's certificate is revoked. */
    public static final String CERT_REVOKED = "QR_CERT_REVOKED";
    /** Revocation status unknown (hard-fail). */
    public static final String REVOCATION_UNKNOWN = "QR_REVOCATION_UNKNOWN";
    /** PS256 signature does not verify. */
    public static final String SIGNATURE_INVALID = "QR_SIGNATURE_INVALID";
    /** Claim (iss, sub, statement, iat/exp …) invalid. */
    public static final String CLAIMS_INVALID = "QR_CLAIMS_INVALID";
    /** aud ≠ RP UUID. */
    public static final String AUDIENCE_MISMATCH = "QR_AUDIENCE_MISMATCH";
    /** sid ≠ session. */
    public static final String SESSION_MISMATCH = "QR_SESSION_MISMATCH";
    /** nonce ≠ your nonce. */
    public static final String NONCE_MISMATCH = "QR_NONCE_MISMATCH";
    /** iat in the future (more than 60 s). */
    public static final String NOT_YET_VALID = "QR_NOT_YET_VALID";
    /** exp + 60 s has passed. */
    public static final String EXPIRED = "QR_EXPIRED";
    /** data (source, fields, photo) limits violated. */
    public static final String DATA_INVALID = "QR_DATA_INVALID";

    private final String code;

    EidQrException(String code, String reason) {
        super(code + ": " + reason);
        this.code = code;
    }

    public String code() {
        return code;
    }
}
