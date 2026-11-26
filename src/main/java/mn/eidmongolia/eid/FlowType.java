package mn.eidmongolia.eid;

/** The flow (response signature.flowType); the RP checks it against what it offered. */
public enum FlowType {
    QR("QR"), APP2APP("App2App"), WEB2APP("Web2App"), NOTIFICATION("Notification");

    private final String wire;

    FlowType(String wire) {
        this.wire = wire;
    }

    /** The RP-API value. */
    public String wireName() {
        return wire;
    }

    /** The constant for an RP-API value, else null. */
    public static FlowType fromWire(String s) {
        for (FlowType f : values()) if (f.wire.equals(s)) return f;
        return null;
    }
}
