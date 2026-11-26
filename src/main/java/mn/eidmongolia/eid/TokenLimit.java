package mn.eidmongolia.eid;

/**
 * 409 TOKEN_LIMIT_REACHED details (Go {@code TokenLimit}): the citizen has {@code limit} valid tokens of {@code kind}
 * (limit 0 = issuance of that kind is closed).
 *
 * @param kind {@link TokenService#KIND_PERSONAL} | {@link TokenService#KIND_ORGANIZATION}
 * @param organization ORGANIZATION only (NTRMN-…); "" otherwise
 */
public record TokenLimit(String kind, int limit, String organization) {
}
