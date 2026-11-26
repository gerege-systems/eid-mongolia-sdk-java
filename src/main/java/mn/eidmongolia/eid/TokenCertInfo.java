package mn.eidmongolia.eid;

/**
 * Discovery's tokenCertificate block (Go {@code TokenCertInfo}). An older CA without the block → enabled false.
 *
 * @param issue the full POST URL
 * @param result the GET URL template ({sessionID})
 * @param permission the RP permission needed (TOKEN_ISSUE)
 * @param onBehalfOf "optional": "" = a personal token
 * @param scopeLockedOnRenewal renewal keeps the scope (else 409 TOKEN_SCOPE_CHANGE); false on older CAs
 * @param appTransaction "optional" when the CA accepts {@link TokenCertInput#appTransaction()}; "" on older CAs
 * @param personalAutoSupersede at the personal limit a new personal token supersedes the old one
 * @param dryRun {@link TokenService#previewCertificate} is supported
 * @param rawJson the block's raw JSON ("" when absent)
 */
public record TokenCertInfo(boolean enabled, String issue, String result, String permission, String certificateLevel,
    String keyAlgorithm, String onBehalfOf, boolean scopeLockedOnRenewal, String appTransaction, boolean personalAutoSupersede,
    boolean dryRun, String rawJson) {
}
