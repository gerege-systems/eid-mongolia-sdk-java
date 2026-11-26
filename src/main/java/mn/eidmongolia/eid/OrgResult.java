package mn.eidmongolia.eid;

/**
 * The session's organisation block (real time from the registry; Go {@code OrgResult}). role/rightType are "" when the
 * right was withdrawn. Labels are in the client language; "" on older CAs.
 */
public record OrgResult(String orgEtsi, String orgName, String role, String roleLabel, String rightType,
    String rightTypeLabel) {
}
