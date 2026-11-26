package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * One of the citizen's certificates (Go {@code PersonCertificate}).
 *
 * @param type AUTH | SIGN | SEAL
 * @param keyMedium MOBILE | TOKEN | HSM
 * @param status VALID | REVOKED | EXPIRED | SUSPENDED
 * @param issuedAt null on older CAs
 * @param revokedAt REVOKED, and rows superseded by renewal / re-enrolment (SUSPENDED, revocationReason "superseded")
 * @param revocationReason RFC 5280 CRLReason name; "" = not revoked
 * @param certValue base64 DER
 * @param organization TOKEN rows bound to an organisation; else null
 * @param tokenSerial TOKEN rows: the USB token's serial; "" otherwise
 */
public record PersonCertificate(String documentNumber, String type, String keyMedium, String serialNumber,
    String certificateLevel, String status, Instant notBefore, Instant notAfter, String issuerDn, Instant issuedAt,
    Instant revokedAt, String revocationReason, String certValue, TokenOrganization organization, String tokenSerial) {

    static PersonCertificate of(Json.Obj o, String op) {
        return new PersonCertificate(o.optString("documentNumber"), o.optString("type"), o.optString("keyMedium"),
            o.optString("serialNumber"), o.optString("certificateLevel"), o.optString("status"), Dto.instant(o, "notBefore", op),
            Dto.instant(o, "notAfter", op), o.optString("issuerDn"), Dto.instant(o, "issuedAt", op), Dto.instant(o, "revokedAt", op),
            o.optString("revocationReason"), o.optString("certValue"), TokenOrganization.of(o.optObj("organization")),
            o.optString("tokenSerial"));
    }
}
