package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * POST /token/auth/challenge (Go {@code TokenAuthChallenge}). The token signs
 * {@link TokenService#tokenAuthDigest}(rpUuid, challenge).
 *
 * @param challenge base64 (32 bytes)
 * @param rpUuid the RP the CA bound it to (lower case) — exactly this string goes into the hash
 */
public record TokenAuthChallenge(String challengeId, String challenge, String rpUuid, Instant expiresAt) {
}
