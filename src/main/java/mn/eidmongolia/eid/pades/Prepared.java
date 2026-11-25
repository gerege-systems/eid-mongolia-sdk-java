package mn.eidmongolia.eid.pades;

/**
 * {@link EidPades#prepare} output.
 *
 * <ul>
 *   <li>{@link #dtbs()} — the 32 bytes the phone/token signs: SHA-256(signedAttrs) (RP-API {@code RAW_DIGEST_SIGNATURE} hash)</li>
 *   <li>{@link #digest()} — messageDigest = SHA-256(ByteRange)</li>
 *   <li>{@link #state()} — opaque, serialisable (same layout as the Go reference) — persist it while waiting for the signature</li>
 *   <li>{@link #placement()} — where the visible stamp was drawn; null without an appearance (PLACEMENT_SPEC.md)</li>
 * </ul>
 */
public final class Prepared {
    private final byte[] dtbs;
    private final byte[] digest;
    private final String docId;
    private final byte[] state;
    private final Placement placement;

    Prepared(byte[] dtbs, byte[] digest, String docId, byte[] state, Placement placement) {
        this.dtbs = dtbs;
        this.digest = digest;
        this.docId = docId;
        this.state = state;
        this.placement = placement;
    }

    public byte[] dtbs() {
        return dtbs.clone();
    }

    public byte[] digest() {
        return digest.clone();
    }

    public String docId() {
        return docId;
    }

    public byte[] state() {
        return state.clone();
    }

    byte[] stateRaw() {
        return state;
    }

    public Placement placement() {
        return placement;
    }
}
