package mn.eidmongolia.eid.login;

import java.time.Instant;
import mn.eidmongolia.eid.AcspContext;

/**
 * A sign-in's server-side state (Go {@code eidlogin.Tx}, TS {@code EidLoginTx}) — what an {@link EidLoginStore} keeps.
 * The browser only holds the HttpOnly cookie {@code <sessionId>.<binding>}; {@code bindingHash} = SHA-256(binding) hex.
 *
 * @param mode qr | push | web2app
 * @param acsp the ACSP context for the validator; null for a decoy
 * @param link the device-link material (QR / Web2App); null for push. Its secret never leaves the server.
 * @param decoy a stand-in push session for a number eID refused (exists only here; never completes)
 */
public record EidLoginTx(String sessionId, String bindingHash, String mode, Instant expiresAt, String vc, AcspContext acsp,
    Link link, boolean decoy) {

    /** QR / Web2App link material (Go {@code eidlogin.Link}); {@link #toString()} hides the token and secret. */
    public record Link(String base, String token, String secret, Instant receivedAt, String lang) {
        @Override
        public String toString() {
            return "Link[base=" + base + ", token=***, secret=***, receivedAt=" + receivedAt + ", lang=" + lang + "]";
        }
    }
}
