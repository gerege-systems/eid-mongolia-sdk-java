package mn.eidmongolia.eid;

import java.util.List;

/**
 * GET /organization/seal-grants/etsi/{personEtsi} (Go {@code OrgSealGrantsResponse}, CA dto.PersonOrgSealGrantsResponse):
 * every organisation the citizen is the registry CEO of, with its live (APPROVED / PENDING) RP seal grants — only this
 * RP's own grants.
 *
 * @param personEtsi the server's value, else the requested ETSI
 * @param organizations never null
 * @param rawJson the server's raw JSON
 */
public record OrgSealGrantsResponse(String personEtsi, List<OrgSealGrants> organizations, String rawJson) {
}
