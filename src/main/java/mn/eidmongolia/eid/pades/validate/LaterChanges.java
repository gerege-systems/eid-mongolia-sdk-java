package mn.eidmongolia.eid.pades.validate;

/** Summary of the revisions after a signature's range (TS revisions.ts LaterChanges). */
final class LaterChanges {
    final boolean signaturesOnly;
    final int signatures;
    final boolean visible;

    LaterChanges(boolean signaturesOnly, int signatures, boolean visible) {
        this.signaturesOnly = signaturesOnly;
        this.signatures = signatures;
        this.visible = visible;
    }

    static final LaterChanges NOTHING = new LaterChanges(false, 0, false);
}
