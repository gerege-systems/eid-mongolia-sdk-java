package mn.eidmongolia.eid;

import java.security.cert.X509Certificate;

/**
 * The signer a certificate choice verified ({@link ResponseValidator#validateCertificateChoice}; Go {@code Signer}, TS
 * {@code Signer}). Pass {@link #ref()} to {@code client.sign().digestForSigner} / {@code deviceLinkForSigner}, and
 * {@link #certificate()} as {@link ValidateSignOptions.Builder#expectedCertificate} when validating that signature.
 *
 * @param documentNumber the EXACT device that chose the certificate — the sign session is started for it
 * @param certificate the citizen's SIGN certificate (KeyUsage contentCommitment)
 * @param certificateDerB64 the certificate DER, standard base64
 * @param certChoiceSessionId the certificate-choice session (linked sign's linkedSessionID); "" / null = the
 *     /notification/document route
 */
public record Signer(String documentNumber, X509Certificate certificate, String certificateDerB64,
    CertificateLevel certificateLevel, Subject subject, String certChoiceSessionId) {

    /** The routing part for {@link SignService} ({@link SignerRef}). */
    public SignerRef ref() {
        return new SignerRef(documentNumber, certChoiceSessionId);
    }
}
