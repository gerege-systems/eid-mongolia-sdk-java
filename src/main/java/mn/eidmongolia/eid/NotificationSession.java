package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * A started push (notification) session (Go {@code NotificationSession}).
 *
 * @param vc the 5-digit verification code to SHOW to the user (to compare with the phone) — it is NOT a PIN
 * @param rpChallenge the RP challenge sent (base64); "" for a signature session
 * @param acsp the authentication context for the validator; null for a signature session
 * @param sign the signature request values; null for authentication / certificate choice
 * @param expiresAt the CA's expiresAt; for older CAs computed for sign / certificate choice
 *     ({@link EidClient#sessionExpiry}); null for authentication on an older CA
 */
public record NotificationSession(String sessionId, String vc, String rpChallenge, AcspContext acsp, SignContext sign,
    Instant expiresAt) {
}
