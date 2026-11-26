package mn.eidmongolia.eid;

/** The session's flow: auth = authentication, sign = signature, cert = certificate choice. */
public enum DeviceLinkSessionType {
    AUTH("auth", "ACSP_V2"), SIGN("sign", "RAW_DIGEST_SIGNATURE"), CERT("cert", "");

    private final String wire;
    private final String protocol;

    DeviceLinkSessionType(String wire, String protocol) {
        this.wire = wire;
        this.protocol = protocol;
    }

    /** The link's sessionType value. */
    public String wireName() {
        return wire;
    }

    /** The signature protocol in the authCode payload (Go {@code protocolOf}). */
    String protocol() {
        return protocol;
    }

    /** The constant for a wire value, else null. */
    public static DeviceLinkSessionType fromWire(String s) {
        for (DeviceLinkSessionType t : values()) if (t.wire.equals(s)) return t;
        return null;
    }
}
