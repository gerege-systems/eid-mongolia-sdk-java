package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * One RP's right to use an organisation's seal (Go {@code OrgSealGrant}, CA dto.MobileSealGrant).
 *
 * @param status APPROVED | PENDING ({@link SealGrant#STATUS_APPROVED} …)
 * @param expiresAt PENDING only; else null
 * @param sealCount successful seals by this RP in the organisation's name; null = unknown (the CA could not read its
 *     statistics — not 0)
 * @param sealCount30d the same for the last 30 days; null = unknown
 * @param lastSealedAt null = never (or unknown)
 */
public record OrgSealGrant(String grantId, String rpName, String rpDomain, String status, Instant createdAt,
    Instant decidedAt, Instant expiresAt, String approverName, Long sealCount, Long sealCount30d, Instant lastSealedAt) {

    static OrgSealGrant of(Json.Obj o, String op) {
        return new OrgSealGrant(o.optString("grantId"), o.optString("rpName"), o.optString("rpDomain"), o.optString("status"),
            Dto.instant(o, "createdAt", op), Dto.instant(o, "decidedAt", op), Dto.instant(o, "expiresAt", op),
            o.optString("approverName"), Dto.optLongOrNull(o, "sealCount"), Dto.optLongOrNull(o, "sealCount30d"),
            Dto.instant(o, "lastSealedAt", op));
    }
}
