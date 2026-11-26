package mn.eidmongolia.eid;

/**
 * {@link QrService#start} result (Go {@code QRSession}). Store it (a stateless RP can keep it in its own session) and
 * pass it to {@link QrService#result} / {@link QrService#check} / {@link QrService#verify}.
 */
public record QrSession(String sessionId, String nonce) {
}
