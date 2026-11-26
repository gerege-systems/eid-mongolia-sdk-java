package mn.eidmongolia.eid;

/**
 * One issued certificate (Go {@code TokenCertItem}).
 *
 * @param certificate base64 DER
 */
public record TokenCertItem(String certificate, String certificatePem, String serialHex, String notBefore, String notAfter) {

    static TokenCertItem of(Json.Obj o) {
        return o == null ? null : new TokenCertItem(o.optString("certificate"), o.optString("certificatePem"), o.optString("serialHex"),
            o.optString("notBefore"), o.optString("notAfter"));
    }
}
