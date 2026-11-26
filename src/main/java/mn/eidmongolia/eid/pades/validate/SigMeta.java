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

    SigMeta(int revIndex, String role, boolean roleOK, boolean seal) {
        this.revIndex = revIndex;
        this.role = role;
        this.roleOK = roleOK;
        this.seal = seal;
    }
}
