package mn.eidmongolia.eid;

/** Session counts per flow (Go {@code ActivityCounts}). */
public record ActivityCounts(int authentication, int signature) {

    static ActivityCounts of(Json.Obj o) {
        return new ActivityCounts(Dto.integer(o, "authentication"), Dto.integer(o, "signature"));
    }
}
