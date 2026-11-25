package mn.eidmongolia.eid.pades;

/** {@code phone} (RP-API RAW_DIGEST_SIGNATURE session) | {@code token} (USB token). */
public enum Medium {
    PHONE("phone"),
    TOKEN("token");

    private final String wire;

    Medium(String wire) {
        this.wire = wire;
    }

    public String wire() {
        return wire;
    }
}
