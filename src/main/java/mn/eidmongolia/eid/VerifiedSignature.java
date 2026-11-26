package mn.eidmongolia.eid;

import java.security.cert.X509Certificate;

/**
 * A verified signature (signing; Go {@code VerifiedSignature}, TS {@code VerifiedSignature}).
 *
 * @param signatureValueB64 the signature (base64) over the RP's digest
 * @param signatureAlgorithm the response's algorithm, e.g. rsassa-pss
 * @param certificateLevel the effective level (as {@link VerifiedIdentity#certificateLevel()})
 */
public record VerifiedSignature(String documentNumber, String signatureValueB64, String signatureAlgorithm,
    X509Certificate certificate, Subject subject, String subjectDn, CertificateLevel certificateLevel) {
}
