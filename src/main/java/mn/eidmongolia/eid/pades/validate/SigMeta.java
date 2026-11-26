package mn.eidmongolia.eid.pades.validate;

/** Data of a verified signature that its visible stamp depends on (TS revisions.ts SigMeta), keyed by object number. */
final class SigMeta {
    /** Order by ByteRange end (1-based). */
    int revIndex;
    /** The single claimedRole of signer-attributes-v2 ("" when absent). */
    String role;
    /** claimedRole count is 0 or exactly 1. */
    boolean roleOK;
    /** The signer certificate is an e-Seal certificate (APPEARANCE_SPEC.md §6.1): only the seal stamp is accepted. */
    boolean seal;
    // The stamp's /Name is NOT compared with the certificate name (corpus v15, Go appearance.go sigMeta): the released
    // eID desktop client writes the Cyrillic portal name while the certificate name is Latin, integrators may pass their
    // own signerName, and an untrusted signer chooses its own certificate name anyway. signer_name stays from the certificate.

    SigMeta(int revIndex, String role, boolean roleOK, boolean seal) {
        this.revIndex = revIndex;
        this.role = role;
        this.roleOK = roleOK;
        this.seal = seal;
    }
}
