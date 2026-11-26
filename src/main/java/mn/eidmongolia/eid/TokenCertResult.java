package mn.eidmongolia.eid;

import java.util.List;

/**
 * GET /token/certificate/{sessionID} (Go {@code TokenCertResult}; only the creating RP, idempotent for 24 h). Check it
 * with {@link TokenService#verifyTokenCertificates} before writing to the token.
 *
 * @param auth null when absent
 * @param sign null when absent
 * @param chain base64 DER: 04, 03, 02 (no root)
 * @param organization null for a personal token
 */
public record TokenCertResult(String status, TokenCertItem auth, TokenCertItem sign, List<String> chain, String chainPem,
    TokenOrganization organization, String keyMedium, String certificateLevel, String rawJson) {
}
