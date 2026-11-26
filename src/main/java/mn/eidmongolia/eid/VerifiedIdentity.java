package mn.eidmongolia.eid;

import java.security.cert.X509Certificate;

/**
 * A verified citizen (authentication; Go {@code VerifiedIdentity}, TS {@code VerifiedIdentity}).
 *
 * @param certificate the citizen's X.509 certificate
 * @param subject the parsed subject (name, ETSI identifier)
 * @param subjectDn the raw subject DN (RFC 2253)
 * @param certificateLevel the effective level: the response's certificateLevel, never above what the certificate
 *     supports ({@link ResponseValidator#certificateLevelOf})
 */
public record VerifiedIdentity(String documentNumber, X509Certificate certificate, Subject subject, String subjectDn,
    CertificateLevel certificateLevel) {
}
