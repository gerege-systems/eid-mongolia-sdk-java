package mn.eidmongolia.eid;

/**
 * An organisation the citizen may represent (Go {@code Representation}, TS {@code Representation}). Labels are in the
 * client language ({@link EidClient.Builder#language}); "" on older CAs. Absent fields are "".
 *
 * @param orgEtsi NTRMN-&lt;registry&gt; — the value for onBehalfOf
 * @param role the machine role (ceo / founder / stakeholder, or the ADMIN's text for MANAGER) — show {@code roleLabel}
 * @param rightType ADMIN | MANAGER
 * @param source REGISTRY | MANUAL
 * @param claimedRole the CMS signer-attributes-v2 claimed role for PAdES on behalf of this organisation, passed through
 *     unchanged ({@code PrepareOptions.claimedRole}); "" when too long or on older CAs
 * @param validFrom ISO 8601
 * @param validTo ISO 8601; "" = no end
 */
public record Representation(String orgEtsi, String orgRegister, String orgName, String orgNameEn, String role,
    String roleLabel, String rightType, String rightTypeLabel, String source, String sourceLabel, String claimedRole,
    String validFrom, String validTo) {

    static Representation of(Json.Obj o) {
        return new Representation(o.optString("orgEtsi"), o.optString("orgRegister"), o.optString("orgName"),
            o.optString("orgNameEn"), o.optString("role"), o.optString("roleLabel"), o.optString("rightType"),
            o.optString("rightTypeLabel"), o.optString("source"), o.optString("sourceLabel"), o.optString("claimedRole"),
            o.optString("validFrom"), o.optString("validTo"));
    }
}
