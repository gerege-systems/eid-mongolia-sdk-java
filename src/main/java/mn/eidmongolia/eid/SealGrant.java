package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * POST /seal/grants (202) and GET /seal/grants/{grantId} (Go {@code SealGrant}, CA dto.RPSealGrantStatus). The approver's
 * ETSI / PIN2 session is never disclosed to the RP.
 *
 * @param status {@link #STATUS_PENDING} … {@link #STATUS_REVOKED}
 * @param expiresAt the end of the PENDING request's approval window (the grant itself has no end)
 * @param approvedAt when the CEO approved (APPROVED, or REVOKED after approval); else null
 * @param failure FAILED / EXPIRED / REVOKED code: EXPIRED, PUSH_FAILED, RP_NOT_ACTIVE, ORG_NOT_ACTIVE, RP_CHANGED,
 *     RP_PERMISSIONS_FULL, CANCELLED, ORG_REVOKED; else ""
 */
public record SealGrant(String grantId, String orgEtsi, String status, Instant expiresAt, Instant approvedAt,
    Instant revokedAt, String failure) {

    public static final String STATUS_PENDING = "PENDING";
    /** The right exists — {@link SealService#seal} / {@link SealService#requestCertificate} work. */
    public static final String STATUS_APPROVED = "APPROVED";
    public static final String STATUS_REJECTED = "REJECTED";
    public static final String STATUS_EXPIRED = "EXPIRED";
    /** {@link #failure()} carries the code. */
    public static final String STATUS_FAILED = "FAILED";
    /** Revoked after approval (by the CEO in the app, or the operator). */
    public static final String STATUS_REVOKED = "REVOKED";
    /** {@link EidException.SealGrantFailed#outcome()} only: the wait's timeout passed (not a server state). */
    public static final String STATUS_TIMEOUT = "TIMEOUT";

    static SealGrant of(Json.Obj o, String op) {
        return new SealGrant(o.optString("grantId"), o.optString("orgEtsi"), o.optString("status"), Dto.instant(o, "expiresAt", op),
            Dto.instant(o, "approvedAt", op), Dto.instant(o, "revokedAt", op), o.optString("failure"));
    }
}
