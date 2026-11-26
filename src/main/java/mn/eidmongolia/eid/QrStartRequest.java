package mn.eidmongolia.eid;

/**
 * {@link QrService#start} input (Go {@code QRStartRequest}).
 *
 * @param qr the scanned content ("EIDMN-QR1:&lt;token&gt;")
 * @param nonce the RP's nonce (16–128 printable ASCII 0x21–0x7E, e.g. an order number), returned in the JWS; null / "" =
 *     base64url(16 random bytes), 22 characters
 * @param relyingPartyName a sub-system label (e.g. «Касс 3», logs); null / "" = Credentials.rpName. The name the citizen
 *     sees is the CA registry's (the JWS rp_name).
 */
public record QrStartRequest(String qr, String nonce, String relyingPartyName) {
    public QrStartRequest(String qr) {
        this(qr, null, null);
    }
}
