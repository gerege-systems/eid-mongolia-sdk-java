package mn.eidmongolia.eid;

/**
 * The signing device chosen by certificate choice (TS {@code SignerRef}; the routing part of Go {@code Signer}): the
 * result of the validator's certificate-choice check, or values stored from it.
 *
 * @param documentNumber the EXACT device that chose the certificate — the sign session is started for it
 * @param certChoiceSessionId the certificate-choice session (linked sign's linkedSessionID); null / "" = the
 *     /notification/document route
 */
public record SignerRef(String documentNumber, String certChoiceSessionId) {
}
