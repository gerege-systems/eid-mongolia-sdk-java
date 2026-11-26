package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * POST /seal/certificate/{orgEtsi} (202) and GET /seal/certificate/{orgEtsi}/requests/{requestId} (Go
 * {@code SealCertificateRequest}).
 *
 * @param status {@link #STATUS_PENDING} … {@link #STATUS_FAILED}
 * @param expiresAt the approval window's end (then EXPIRED)
 * @param decidedAt null while undecided
 * @param approvers ADMINs a PIN2 push went to (new / PENDING answers)
 * @param failure FAILED / EXPIRED code: EXPIRED | SEAL_ISSUANCE_FAILED | PUSH_FAILED | SEAL_SERVICE_DISABLED; else ""
 * @param certificate set when ISSUED; else null
 */
public record SealCertificateRequest(String requestId, String orgEtsi, String status, Instant createdAt, Instant expiresAt,
    Instant decidedAt, int approvers, String failure, SealCertificate certificate) {

    public static final String STATUS_PENDING = "PENDING";
    /** Approved, the certificate is being issued. */
    public static final String STATUS_APPROVED = "APPROVED";
    /** {@link #certificate()} is set. */
    public static final String STATUS_ISSUED = "ISSUED";
    public static final String STATUS_REJECTED = "REJECTED";
    public static final String STATUS_EXPIRED = "EXPIRED";
    public static final String STATUS_FAILED = "FAILED";
    /** {@link EidException.SealRequestFailed#outcome()} only: the wait's timeout passed (not a server state). */
    public static final String STATUS_TIMEOUT = "TIMEOUT";

    static SealCertificateRequest of(Json.Obj o, String op) {
        return new SealCertificateRequest(o.optString("requestId"), o.optString("orgEtsi"), o.optString("status"),
            Dto.instant(o, "createdAt", op), Dto.instant(o, "expiresAt", op), Dto.instant(o, "decidedAt", op), Dto.integer(o, "approvers"),
            o.optString("failure"), SealCertificate.of(o.optObj("certificate"), op));
    }
}
