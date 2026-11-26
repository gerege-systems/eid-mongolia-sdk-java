package mn.eidmongolia.eid;

/**
 * Extra checks of {@link ResponseValidator#validateAuth} — the device-link relay guard (Go {@code ValidateAuthOptions},
 * TS {@code ValidateAuthOptions}).
 */
public final class ValidateAuthOptions {
    /** No extra checks. */
    public static final ValidateAuthOptions NONE = builder().build();

    final FlowType expectedFlowType;
    final String userChallengeVerifier;

    private ValidateAuthOptions(Builder b) {
        this.expectedFlowType = b.expectedFlowType;
        this.userChallengeVerifier = b.userChallengeVerifier;
    }

    public static Builder builder() {
        return new Builder();
    }

    public FlowType expectedFlowType() {
        return expectedFlowType;
    }

    public String userChallengeVerifier() {
        return userChallengeVerifier;
    }

    /** {@link ValidateAuthOptions} fields. */
    public static final class Builder {
        private FlowType expectedFlowType;
        private String userChallengeVerifier;

        private Builder() {
        }

        /**
         * The flow the RP SHOWED (or push). When given, the signed flowType must be EXACTLY it: QR page → QR; the
         * button in a mobile browser → WEB2APP; the button in the RP's app → APP2APP; push → NOTIFICATION. WEB2APP /
         * APP2APP require {@link #userChallengeVerifier}. A page showing both QR and button: check a result that came
         * through the callback (with the verifier) as WEB2APP / APP2APP, one that came by polling as QR.
         */
        public Builder expectedFlowType(FlowType v) {
            expectedFlowType = v;
            return this;
        }

        /**
         * The callback URL's userChallengeVerifier parameter (same-device flows). When given,
         * BASE64URL(SHA-256(verifier)) must equal the signed userChallenge.
         */
        public Builder userChallengeVerifier(String v) {
            userChallengeVerifier = v;
            return this;
        }

        public ValidateAuthOptions build() {
            return new ValidateAuthOptions(this);
        }
    }
}
