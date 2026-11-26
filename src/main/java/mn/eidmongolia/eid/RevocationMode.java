package mn.eidmongolia.eid;

/** How an unknown revocation status is decided (Go {@code RevocationMode}, TS {@code revocationMode}). */
public enum RevocationMode {
    /** Unknown → {@link EidException.Validation} (the default). */
    HARD_FAIL("hard-fail"),
    /** Unknown → accepted ({@link RevocationOutcome#UNCHECKED}). */
    SOFT_FAIL("soft-fail");

    private final String wire;

    RevocationMode(String wire) {
        this.wire = wire;
    }

    /** "hard-fail" | "soft-fail". */
    public String wireName() {
        return wire;
    }
}
