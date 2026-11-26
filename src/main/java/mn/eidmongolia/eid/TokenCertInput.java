package mn.eidmongolia.eid;

/**
 * POST /token/certificate input (Go {@code TokenCertInput}).
 *
 * @param signerEtsi the citizen (PNOMN-…); the approval push goes to their phone
 * @param csrAuth PKCS#10 DER (EC P-256, ecdsa-with-SHA256, ≤ 4 KiB) — a different key than csrSign
 * @param csrSign PKCS#10 DER
 * @param tokenSerial the token's serial ([A-Za-z0-9-]{1,64})
 * @param tokenLabel optional (≤ 64); null / "" = not sent
 * @param onBehalfOf an organisation token (NTRMN-…); null / "" = a personal token
 * @param appTransaction optional macOS App Store StoreKit 2 AppTransaction JWS (≤ {@link TokenService#MAX_APP_TRANSACTION_BYTES});
 *     null / "" = not sent
 */
public record TokenCertInput(String signerEtsi, byte[] csrAuth, byte[] csrSign, String tokenSerial, String tokenLabel,
    String onBehalfOf, String appTransaction) {

    public TokenCertInput {
        csrAuth = csrAuth == null ? null : csrAuth.clone();
        csrSign = csrSign == null ? null : csrSign.clone();
    }

    @Override
    public byte[] csrAuth() {
        return csrAuth == null ? null : csrAuth.clone();
    }

    @Override
    public byte[] csrSign() {
        return csrSign == null ? null : csrSign.clone();
    }
}
