package mn.eidmongolia.eid;

/** Signature algorithm. rsassa-pss is the default; ecdsa-with-SHA256 is the legacy threshold-ECDSA certificate. */
public enum SignatureAlgorithm {
    RSASSA_PSS("rsassa-pss"),
    SHA256_WITH_RSA("sha256WithRSAEncryption"),
    SHA384_WITH_RSA("sha384WithRSAEncryption"),
    SHA512_WITH_RSA("sha512WithRSAEncryption"),
    ECDSA_WITH_SHA256("ecdsa-with-SHA256");

    private final String wire;

    SignatureAlgorithm(String wire) {
        this.wire = wire;
    }

    /** The RP-API value. */
    public String wireName() {
        return wire;
    }

    /** The constant for an RP-API value, else null. */
    public static SignatureAlgorithm fromWire(String s) {
        for (SignatureAlgorithm a : values()) if (a.wire.equals(s)) return a;
        return null;
    }
}
