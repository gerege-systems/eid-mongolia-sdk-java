package mn.eidmongolia.eid;

/** Certificate counts by status (Go {@code CertCounts}). */
public record CertCounts(int valid, int revoked, int expired, int suspended, int total) {

    static CertCounts of(Json.Obj o) {
        return new CertCounts(Dto.integer(o, "valid"), Dto.integer(o, "revoked"), Dto.integer(o, "expired"),
            Dto.integer(o, "suspended"), Dto.integer(o, "total"));
    }
}
