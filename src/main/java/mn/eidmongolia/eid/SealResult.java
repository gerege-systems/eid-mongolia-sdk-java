package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * POST /seal/{orgEtsi} (Go {@code SealResult}, CA dto.SealResponse) — already checked by
 * {@link SealService#seal}: the ECDSA signature verifies over the digest with the e-Seal certificate.
 *
 * @param signature ECDSA signature over the digest (ASN.1 DER)
 * @param signatureAlgorithm e.g. ecdsa-with-SHA256 (from the digest's hash)
 * @param certificate the sealing certificate (DER)
 * @param certificateLevel that certificate's own level (QcSSCD → QSCD, else QUALIFIED)
 * @param rawJson the server's raw JSON
 */
public record SealResult(String orgEtsi, byte[] signature, String signatureAlgorithm, byte[] certificate,
    String certificateLevel, Instant sealedAt, String rawJson) {

    public SealResult {
        signature = signature.clone();
        certificate = certificate.clone();
    }

    @Override
    public byte[] signature() {
        return signature.clone();
    }

    @Override
    public byte[] certificate() {
        return certificate.clone();
    }
}
