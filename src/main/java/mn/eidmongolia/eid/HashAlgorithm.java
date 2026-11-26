package mn.eidmongolia.eid;

/** Hash algorithm (Smart-ID v3 names). */
public enum HashAlgorithm {
    SHA_256("SHA-256", "SHA-256"), SHA_384("SHA-384", "SHA-384"), SHA_512("SHA-512", "SHA-512");

    private final String wire;
    private final String jca;

    HashAlgorithm(String wire, String jca) {
        this.wire = wire;
        this.jca = jca;
    }

    /** The RP-API value ("SHA-256" | "SHA-384" | "SHA-512"). */
    public String wireName() {
        return wire;
    }

    /** The {@link java.security.MessageDigest} algorithm name. */
    String jcaName() {
        return jca;
    }

    /** The constant for an RP-API value, else null. */
    public static HashAlgorithm fromWire(String s) {
        for (HashAlgorithm h : values()) if (h.wire.equals(s)) return h;
        return null;
    }
}
