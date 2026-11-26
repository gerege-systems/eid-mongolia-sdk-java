package mn.eidmongolia.eid;

import java.util.List;

/**
 * Stable CA error codes — {@link EidException#code()} (Go {@code errors.go}, {@code seal.go}, {@code seal_grant.go},
 * {@code pdfregister.go}, {@code qr.go}; TS {@code errors.ts}). The same strings in every SDK — branch on them, never on
 * messages.
 */
public final class EidErrorCodes {
    private EidErrorCodes() {
    }

    // Session start (CA 2026-10-14).
    /** 409: no active device / SIGN credential / valid signing certificate (sign and certificate-choice start). */
    public static final String NO_SIGNING_CERTIFICATE = "NO_SIGNING_CERTIFICATE";
    /** 409: linked sign's linkedSessionID (certificate-choice) invalid / stale / other documentNumber / used. */
    public static final String CERT_CHOICE_INVALID = "CERT_CHOICE_INVALID";
    /** 400: request body/field invalid. A programming error. */
    public static final String REQUEST_INVALID = "REQUEST_INVALID";

    // Temporary (retryable) errors.
    /** 429: rate limit; Retry-After. */
    public static final String RATE_LIMITED = "RATE_LIMITED";
    /** 503: state store temporarily unreachable; Retry-After: 5. */
    public static final String STATE_UNAVAILABLE = "STATE_UNAVAILABLE";
    /** 503: token certificate still being issued; Retry-After: 5. */
    public static final String ISSUANCE_PENDING = "ISSUANCE_PENDING";

    // onBehalfOf.
    public static final String REPRESENTATION_DENIED = "REPRESENTATION_DENIED";
    public static final String REPRESENTATION_PENDING = "REPRESENTATION_PENDING";
    public static final String REPRESENTATION_EXPIRED = "REPRESENTATION_EXPIRED";
    /** Organisation not ACTIVE: 403 in onBehalfOf flows ({@link EidException.Forbidden}), 409 on seal routes. */
    public static final String ORG_NOT_ACTIVE = "ORG_NOT_ACTIVE";
    public static final String SIGNER_UNIDENTIFIED = "SIGNER_UNIDENTIFIED";
    public static final String ORG_NOT_FOUND = "ORG_NOT_FOUND";
    public static final String REPRESENTATION_REVOKED = "REPRESENTATION_REVOKED";

    // «My QR».
    /** 404: QR token unknown / expired (120 s) / already used. */
    public static final String QR_TOKEN_INVALID = "QR_TOKEN_INVALID";

    // Seal routes (/seal/*).
    public static final String SEAL_NOT_ISSUED = "SEAL_NOT_ISSUED";
    public static final String SEAL_CERT_REVOKED = "SEAL_CERT_REVOKED";
    public static final String SEAL_KEY_UNAVAILABLE = "SEAL_KEY_UNAVAILABLE";
    public static final String SEAL_CERT_EXPIRED = "SEAL_CERT_EXPIRED";
    public static final String SEAL_CERT_NOT_YET_VALID = "SEAL_CERT_NOT_YET_VALID";
    public static final String SEAL_APPROVER_UNAVAILABLE = "SEAL_APPROVER_UNAVAILABLE";
    public static final String SEAL_REQUEST_NOT_FOUND = "SEAL_REQUEST_NOT_FOUND";
    /** 503: the operator switched the seal service off platform-wide — never retryable. */
    public static final String SEAL_SERVICE_DISABLED = "SEAL_SERVICE_DISABLED";
    /** {@link EidException.Api#service()} of {@link #SEAL_SERVICE_DISABLED}: certificate issuance. */
    public static final String SEAL_SERVICE_ISSUANCE = "issuance";
    /** {@link EidException.Api#service()} of {@link #SEAL_SERVICE_DISABLED}: sealing. */
    public static final String SEAL_SERVICE_SEALING = "sealing";

    // Seal grants (/seal/grants).
    public static final String RP_NOT_REGISTERED = "RP_NOT_REGISTERED";
    public static final String NOT_ORG_CEO = "NOT_ORG_CEO";
    public static final String AUTH_SESSION_NOT_FOUND = "AUTH_SESSION_NOT_FOUND";
    public static final String AUTH_SESSION_WRONG_FLOW = "AUTH_SESSION_WRONG_FLOW";
    public static final String AUTH_SESSION_NOT_COMPLETED = "AUTH_SESSION_NOT_COMPLETED";
    public static final String AUTH_SESSION_TOO_OLD = "AUTH_SESSION_TOO_OLD";
    public static final String AUTH_SESSION_ALREADY_USED = "AUTH_SESSION_ALREADY_USED";
    public static final String RP_NOT_ACTIVE = "RP_NOT_ACTIVE";
    public static final String SEAL_GRANT_ALREADY_APPROVED = "SEAL_GRANT_ALREADY_APPROVED";
    public static final String RP_PERMISSIONS_FULL = "RP_PERMISSIONS_FULL";
    public static final String SEAL_GRANT_NOT_FOUND = "SEAL_GRANT_NOT_FOUND";

    // POST /pdf/signatures.
    public static final String REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE";
    public static final String CMS_INVALID = "CMS_INVALID";
    public static final String SIGNATURE_INVALID = "SIGNATURE_INVALID";
    public static final String TIMESTAMP_INVALID = "TIMESTAMP_INVALID";
    public static final String SIGNER_MISMATCH = "SIGNER_MISMATCH";
    public static final String SIGNER_CERT_INVALID = "SIGNER_CERT_INVALID";
    public static final String TOKEN_CERT_INVALID = "TOKEN_CERT_INVALID";
    public static final String TOKEN_ORG_MISMATCH = "TOKEN_ORG_MISMATCH";
    public static final String SESSION_MISMATCH = "SESSION_MISMATCH";
    public static final String SESSION_NOT_COMPLETE = "SESSION_NOT_COMPLETE";
    public static final String SESSION_FAILED = "SESSION_FAILED";
    public static final String CLAIMED_ROLE_MISMATCH = "CLAIMED_ROLE_MISMATCH";
    public static final String DOC_ID_CONFLICT = "DOC_ID_CONFLICT";
    public static final String REGISTRY_CONFLICT = "REGISTRY_CONFLICT";
    public static final String DOC_NOT_FOUND = "DOC_NOT_FOUND";
    public static final String PRIOR_MISMATCH = "PRIOR_MISMATCH";

    /** Codes {@link EidException.Api#retryable()} recognises (Go {@code RetryableCodes}, TS {@code RETRYABLE_ERROR_CODES}). */
    public static final List<String> RETRYABLE = List.of(RATE_LIMITED, STATE_UNAVAILABLE, ISSUANCE_PENDING);

    /** All onBehalfOf refusal codes (Go {@code OnBehalfErrorCodes}, same order). */
    public static final List<String> ON_BEHALF = List.of(REPRESENTATION_DENIED, REPRESENTATION_PENDING,
        REPRESENTATION_EXPIRED, ORG_NOT_ACTIVE, SIGNER_UNIDENTIFIED, ORG_NOT_FOUND, REPRESENTATION_REVOKED);

    /** Seal route codes (Go {@code SealErrorCodes}, TS {@code SEAL_ERROR_CODES}, same order). */
    public static final List<String> SEAL = List.of(ORG_NOT_ACTIVE, SEAL_NOT_ISSUED, SEAL_CERT_REVOKED,
        SEAL_KEY_UNAVAILABLE, SEAL_CERT_EXPIRED, SEAL_CERT_NOT_YET_VALID, SEAL_APPROVER_UNAVAILABLE,
        SEAL_REQUEST_NOT_FOUND, SEAL_SERVICE_DISABLED);

    /** Seal grant codes (Go {@code SealGrantErrorCodes}, same order; 400 REQUEST_INVALID and 429 RATE_LIMITED excluded). */
    public static final List<String> SEAL_GRANT = List.of(RP_NOT_REGISTERED, NOT_ORG_CEO, AUTH_SESSION_NOT_FOUND,
        ORG_NOT_FOUND, AUTH_SESSION_WRONG_FLOW, AUTH_SESSION_NOT_COMPLETED, AUTH_SESSION_TOO_OLD,
        AUTH_SESSION_ALREADY_USED, ORG_NOT_ACTIVE, RP_NOT_ACTIVE, SEAL_GRANT_ALREADY_APPROVED, RP_PERMISSIONS_FULL,
        SEAL_APPROVER_UNAVAILABLE, SEAL_GRANT_NOT_FOUND);

    /** POST /pdf/signatures codes (Go {@code PDFRegisterErrorCodes}, TS {@code PDF_REGISTER_ERROR_CODES}, same order). */
    public static final List<String> PDF_REGISTER = List.of(REQUEST_INVALID, REQUEST_TOO_LARGE, CMS_INVALID,
        SIGNATURE_INVALID, TIMESTAMP_INVALID, SIGNER_MISMATCH, SIGNER_CERT_INVALID, TOKEN_CERT_INVALID,
        TOKEN_ORG_MISMATCH, SESSION_MISMATCH, SESSION_NOT_COMPLETE, SESSION_FAILED, CLAIMED_ROLE_MISMATCH,
        REPRESENTATION_REVOKED, DOC_ID_CONFLICT, REGISTRY_CONFLICT, DOC_NOT_FOUND, PRIOR_MISMATCH, RATE_LIMITED,
        STATE_UNAVAILABLE);
}
