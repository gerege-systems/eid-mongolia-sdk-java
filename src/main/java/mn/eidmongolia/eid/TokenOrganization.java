package mn.eidmongolia.eid;

/** The organisation a USB token is bound to (Go {@code TokenOrganization}). */
public record TokenOrganization(String etsi, String name) {

    /** null when the member is absent or has no etsi (a personal token). */
    static TokenOrganization of(Json.Obj o) {
        if (o == null) return null;
        String etsi = o.optString("etsi");
        return etsi.isEmpty() ? null : new TokenOrganization(etsi, o.optString("name"));
    }
}
