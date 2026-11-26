package mn.eidmongolia.eid;

import java.util.Base64;

/**
 * ACSP_V2 payload and digest (Go {@code crypto.go} {@code BuildACSPV2Payload} / {@code ACSPV2Digest}, TS
 * {@code buildAcspV2Payload} / {@code acspV2Digest}). The payload is BYTE-IDENTICAL to Smart-ID RP-API v3: server,
 * phone and SDKs join the same '|'-separated string — one byte off and the signature does not match.
 */
public final class Acsp {
    private Acsp() {
    }

    /**
     * The UTF-8 bytes that are signed:
     * {@code schemeName|ACSP_V2|serverRandom|rpChallenge|userChallenge|B64(rpName)|B64(brokeredRpName)|B64(SHA-256(interactions))|interactionTypeUsed|initialCallbackUrl|flowType}.
     */
    public static byte[] buildV2Payload(AcspV2Params p) {
        String scheme = s(p.schemeName());
        if (scheme.isEmpty()) scheme = "smart-id";
        byte[] ih = EidCrypto.digest("SHA-256", EidCrypto.utf8(s(p.interactions())));
        String msg = String.join("|",
            scheme,
            "ACSP_V2",
            s(p.serverRandom()),
            s(p.rpChallenge()),
            s(p.userChallenge()),
            b64(s(p.relyingPartyName())),
            b64(s(p.brokeredRpName())),
            Base64.getEncoder().encodeToString(ih),
            s(p.interactionTypeUsed()),
            s(p.initialCallbackUrl()),
            s(p.flowType()));
        return EidCrypto.utf8(msg);
    }

    /** HASH_{hashAlgorithm}(payload). */
    public static byte[] v2Digest(AcspV2Params p, HashAlgorithm h) {
        return EidCrypto.digest(h.jcaName(), buildV2Payload(p));
    }

    /**
     * HASH_{hashAlgorithm}(payload) by the RP-API name ("SHA-256" | "SHA-384" | "SHA-512").
     *
     * @throws EidException.Validation for any other name
     */
    public static byte[] v2Digest(AcspV2Params p, String hashAlgorithm) {
        HashAlgorithm h = HashAlgorithm.fromWire(hashAlgorithm);
        if (h == null) throw new EidException.Validation("дэмжигдээгүй hashAlgorithm: " + hashAlgorithm);
        return v2Digest(p, h);
    }

    static String b64(String s) {
        return Base64.getEncoder().encodeToString(EidCrypto.utf8(s));
    }

    private static String s(String v) {
        return v == null ? "" : v;
    }
}
