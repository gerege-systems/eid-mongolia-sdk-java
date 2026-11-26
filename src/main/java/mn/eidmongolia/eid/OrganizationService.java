package mn.eidmongolia.eid;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Organisations a citizen can act for ({@link EidClient#organization()}, Go {@code OrganizationService}, TS
 * {@code OrganizationApi}). The citizen must have signed in to your RP within the last 24 h (else 403
 * {@link EidException.Forbidden}).
 */
public final class OrganizationService {
    private final RpHttp http;

    OrganizationService(RpHttp http) {
        this.http = http;
    }

    /**
     * GET /organization/representations/etsi/{personEtsi} — the organisations (ACTIVE, in validity) the citizen may
     * represent, to let them choose before onBehalfOf. The choice is not a trust source: the server checks again when
     * the session starts.
     */
    public RepresentationsResponse getRepresentations(String personEtsi) {
        String path = Routes.ORG_REPRESENTATIONS.expand(personEtsi);
        RpHttp.Result r = http.getJson(path, null);
        Json.Obj o = r.obj("GET /organization/representations/…");
        List<Representation> reps = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "representations")) reps.add(Representation.of(x));
        String pe = o.optString("personEtsi");
        return new RepresentationsResponse(pe.isEmpty() ? personEtsi : pe, Collections.unmodifiableList(reps), Dto.raw(r));
    }

    /**
     * GET /organization/seal-grants/etsi/{personEtsi} (PKI_READ; the citizen signed in to your RP within 24 h, else 403
     * {@link EidException.Forbidden}): the organisations the citizen is the registry CEO of and their RP seal grants
     * (read only; revocation happens in the eID app). Unknown citizen → {@link EidException.Api} 404.
     */
    public OrgSealGrantsResponse sealGrants(String personEtsi) {
        String path = Routes.ORG_SEAL_GRANTS.expand(personEtsi);
        String op = "GET /organization/seal-grants/…";
        RpHttp.Result r = http.getJson(path, null);
        Json.Obj o = r.obj(op);
        List<OrgSealGrants> orgs = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "organizations")) orgs.add(OrgSealGrants.of(x, op));
        String pe = o.optString("personEtsi");
        return new OrgSealGrantsResponse(pe.isEmpty() ? personEtsi : pe, Collections.unmodifiableList(orgs), Dto.raw(r));
    }
}
