package mn.eidmongolia.eid;

/** A revocation checker's answer (Go {@code RevocationStatus} good / revoked / unknown, TS {@code RevocationStatus}). */
public enum RevocationStatus {
    /** The issuer says the certificate is valid. */
    GOOD("good"),
    /** Revoked — also an OCSP «unknown» (the issuer never issued that serial). */
    REVOKED("revoked"),
    /** No acceptable answer; the validator's {@link RevocationMode} decides. */
    UNKNOWN("unknown");

    private final String wire;

    RevocationStatus(String wire) {
        this.wire = wire;
    }

    /** "good" | "revoked" | "unknown". */
    public String wireName() {
        return wire;
    }
}
