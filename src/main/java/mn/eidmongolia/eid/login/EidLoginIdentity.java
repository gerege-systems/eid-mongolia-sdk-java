package mn.eidmongolia.eid.login;

import java.security.cert.X509Certificate;
import mn.eidmongolia.eid.CertificateLevel;
import mn.eidmongolia.eid.FlowType;
import mn.eidmongolia.eid.Person;
import mn.eidmongolia.eid.RevocationOutcome;

/**
 * The verified citizen given to {@link EidLogin.Builder#onSuccess} (Go {@code eidlogin.Identity}, TS
 * {@code EidLoginIdentity}) — only after the response validator (chain + ACSP_V2 + flowType + the Web2App verifier) and
 * the revocation check accepted it.
 *
 * @param sessionId the RP-API session id (audit, or to link a later signature)
 * @param etsi the certificate's SERIALNUMBER (PNOMN-&lt;civil id&gt;) — identify the user BY THIS, never by name
 * @param civilId etsi without PNOMN-; "" when etsi has another form
 * @param givenName the certificate's (Latin) given name
 * @param documentNumber the signing device's UUID (RP-API documentNumber, not an identity document number)
 * @param certificate the authentication certificate (chain checked)
 * @param flowType QR | Notification | Web2App
 * @param person the session's person block (Cyrillic names …) only when it matches the certificate; else null
 * @param revocation good | unchecked (no OCSP answer, soft-fail) | skipped (revocation disabled) — keep it for audit
 */
public record EidLoginIdentity(String sessionId, String etsi, String civilId, String givenName, String surname, String country,
    String documentNumber, CertificateLevel certificateLevel, X509Certificate certificate, FlowType flowType, Person person,
    RevocationOutcome revocation) {
}
