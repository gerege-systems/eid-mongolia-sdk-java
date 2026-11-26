package mn.eidmongolia.eid;

/** Device link type; the app signs exactly this value as flowType (protected by authCode). */
public enum DeviceLinkType {
    QR("QR"), WEB2APP("Web2App"), APP2APP("App2App");

    private final String wire;

    DeviceLinkType(String wire) {
        this.wire = wire;
    }

    /** The link's deviceLinkType value. */
    public String wireName() {
        return wire;
    }
}
