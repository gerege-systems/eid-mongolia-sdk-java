package mn.eidmongolia.eid;

/**
 * What {@link ResponseValidator#checkRevocationStatus} decided when it did not throw (Go {@code RevocationGood} /
 * {@code RevocationUnchecked} / {@code RevocationSkipped}, TS {@code RevocationOutcome}). Revoked, and unknown in
 * hard-fail mode, are {@link EidException.Validation} instead.
 */
public enum RevocationOutcome {
    /** The issuer says the certificate is valid. */
    GOOD("good"),
    /** The status is unknown and the mode is soft-fail — accepted without a check. */
    UNCHECKED("unchecked"),
    /** No revocation checker is configured — not asked. */
    SKIPPED("skipped");

    private final String wire;

    RevocationOutcome(String wire) {
        this.wire = wire;
    }

    /** "good" | "unchecked" | "skipped". */
    public String wireName() {
        return wire;
    }
}
