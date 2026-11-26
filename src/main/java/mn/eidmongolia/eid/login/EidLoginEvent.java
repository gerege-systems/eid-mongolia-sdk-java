package mn.eidmongolia.eid.login;

import java.util.Map;

/**
 * An audit event ({@link EidLogin.Builder#onEvent}; Go {@code OnEvent}, TS {@code onEvent}). meta never carries tokens,
 * secrets or the ID number (PII): push events carry {@code pushKey} = the first 16 bytes of HMAC-SHA256(auditKey,
 * "eid-push-audit:" + id), hex.
 *
 * @param sessionId "" when there is none (push_limited)
 */
public record EidLoginEvent(Kind kind, String sessionId, Map<String, Object> meta) {

    /** Go {@code EventKind} / TS {@code EidLoginEventKind}. */
    public enum Kind {
        /** A push start answered (meta: mode, pushKey, decoy — decoy=true: eID refused the number, nothing was sent). */
        PUSH_SENT("push_sent"),
        /** The push limit was hit, 429 (meta: mode, pushKey). */
        PUSH_LIMITED("push_limited"),
        /** The citizen refused on the phone (endResult USER_REFUSED*; meta: mode, endResult). */
        REFUSED("refused"),
        /** The eID session expired (TIMEOUT, or unknown to eID; meta: mode). */
        EXPIRED("expired"),
        /** COMPLETE/OK but verification failed (meta: mode, reason = validation | revoked | revocation_unavailable). */
        UNVERIFIED("unverified"),
        /** A Web2App callback not bound to the starting browser's session (meta: mode, reason = unbound). */
        FLOW_REFUSED("flow_refused"),
        /** Verified; onSuccess was called (meta: mode, flow, revocation). */
        SUCCESS("success"),
        /** Any other endResult (WRONG_VC, DOCUMENT_UNUSABLE …; meta: mode, endResult). */
        FAILED("failed");

        private final String wire;

        Kind(String wire) {
            this.wire = wire;
        }

        public String wireName() {
            return wire;
        }
    }
}
