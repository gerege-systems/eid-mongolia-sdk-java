package mn.eidmongolia.eid;

import java.util.List;

/**
 * The issuance start (Go {@code TokenCertStart}): the SIGN session on the citizen's phone.
 *
 * @param vc the code to SHOW the citizen (not a PIN)
 * @param csrAuthSha256 hex SHA-256 of the CSR DER (lower case) — checked against the CSR sent
 * @param supersedes personal issuance at the citizen's personal-token limit: the other personal tokens whose AUTH + SIGN
 *     will be revoked (superseded) when this issuance succeeds — warn the citizen before PIN2; empty otherwise
 */
public record TokenCertStart(String sessionId, String vc, String csrAuthSha256, String csrSignSha256, String expiresAt,
    List<TokenSupersede> supersedes) {
}
