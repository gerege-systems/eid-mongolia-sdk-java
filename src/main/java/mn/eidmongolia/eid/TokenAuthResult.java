package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * POST /token/auth/verify (Go {@code TokenAuthResult}): endResult OK and identity.etsi = the certificate's SERIALNUMBER
 * (checked by the SDK).
 *
 * @param organization the token's organisation; null for a personal token
 */
public record TokenAuthResult(TokenIdentity identity, String serialHex, Instant notAfter, TokenOrganization organization,
    String rawJson) {
}
