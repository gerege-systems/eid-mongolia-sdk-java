package mn.eidmongolia.eid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * One organisation in {@link OrgSealGrantsResponse} (Go {@code OrgSealGrants}).
 *
 * @param orgStatus ACTIVE | SUSPENDED | REVOKED | …
 * @param grants never null
 */
public record OrgSealGrants(String orgEtsi, String orgName, String orgStatus, List<OrgSealGrant> grants) {

    static OrgSealGrants of(Json.Obj o, String op) {
        List<OrgSealGrant> g = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "grants")) g.add(OrgSealGrant.of(x, op));
        return new OrgSealGrants(o.optString("orgEtsi"), o.optString("orgName"), o.optString("orgStatus"),
            Collections.unmodifiableList(g));
    }
}
