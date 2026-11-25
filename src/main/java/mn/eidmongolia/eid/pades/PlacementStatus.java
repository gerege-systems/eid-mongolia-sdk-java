package mn.eidmongolia.eid.pades;

/** {@link Placement#status()}; {@link #wire()} = the Go/iOS/.NET string. */
public enum PlacementStatus {
    /** Drawn at the requested spot (it was free). */
    REQUESTED("requested"),
    /** The requested spot was occupied; the stamp moved to free space. */
    MOVED("moved"),
    /** No free spot: drawn at the requested spot over content. */
    OVERLAP("overlap"),
    /** The page could not be scanned within the limits: drawn at the requested spot. */
    UNSCANNED("unscanned");

    private final String wire;

    PlacementStatus(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }
}
