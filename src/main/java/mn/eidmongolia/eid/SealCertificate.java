package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * GET /seal/certificate/{orgEtsi} (Go {@code SealCertificate}, CA dto.SealCertificateResponse). certificateLevel is the
 * CERTIFICATE's own (QcSSCD → QSCD, else QUALIFIED), not the CA's current key setting.
 *
 * @param certificate DER (base64 on the wire)
 */
public record SealCertificate(String orgEtsi, byte[] certificate, String serialNumber, String subjectDn, String issuerDn,
    Instant notBefore, Instant notAfter, String certificateLevel) {

    public SealCertificate {
        certificate = certificate == null ? new byte[0] : certificate.clone();
    }

    @Override
    public byte[] certificate() {
        return certificate.clone();
    }

    /** null when the object is absent. */
    static SealCertificate of(Json.Obj o, String op) {
        if (o == null) return null;
        byte[] der = SealService.b64(o.optString("certificate"));
        if (der == null) throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal certificate base64 биш");
        return new SealCertificate(o.optString("orgEtsi"), der, o.optString("serialNumber"), o.optString("subjectDn"),
            o.optString("issuerDn"), Dto.instant(o, "notBefore", op), Dto.instant(o, "notAfter", op), o.optString("certificateLevel"));
    }
}
