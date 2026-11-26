package mn.eidmongolia.eid;

/**
 * Optional settings of an authentication session (Go {@code AuthOptions}, TS {@code AuthOptions}). Immutable; create
 * with {@link #builder()}. Unset values take the defaults.
 */
public final class AuthOptions {
    static final AuthOptions DEFAULTS = builder().build();

    final CertificateLevel certificateLevel;
    final String callbackUrl;
    final String onBehalfOf;
    final SignatureAlgorithm signatureAlgorithm;
    final HashAlgorithm hashAlgorithm;

    private AuthOptions(Builder b) {
        certificateLevel = b.certificateLevel;
        callbackUrl = b.callbackUrl == null ? "" : b.callbackUrl.strip();
        onBehalfOf = b.onBehalfOf == null ? "" : b.onBehalfOf.strip();
        signatureAlgorithm = b.signatureAlgorithm;
        hashAlgorithm = b.hashAlgorithm;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private CertificateLevel certificateLevel;
        private String callbackUrl;
        private String onBehalfOf;
        private SignatureAlgorithm signatureAlgorithm;
        private HashAlgorithm hashAlgorithm;

        private Builder() {
        }

        /** This session's certLevel. null = the client's default. */
        public Builder certificateLevel(CertificateLevel v) {
            certificateLevel = v;
            return this;
        }

        /**
         * Same-device (Web2App / App2App) return https URL, sent as initialCallbackUrl; App2App and Web2App are then added
         * to the offered flows. Its host must be in the RP's callbackHosts. Trimmed; null / "" = none.
         */
        public Builder callbackUrl(String v) {
            callbackUrl = v;
            return this;
        }

        /**
         * Sign in on behalf of an organisation: its ETSI (NTRMN-&lt;register&gt;). The server checks the representation
         * (403 {@link EidException.Forbidden#code()} when refused) and returns {@link SessionResult#onBehalfOf()}. The
         * organisation is NOT part of the ACSP_V2 signature — read it from the session result only. Trimmed.
         */
        public Builder onBehalfOf(String v) {
            onBehalfOf = v;
            return this;
        }

        /** null = rsassa-pss. */
        public Builder signatureAlgorithm(SignatureAlgorithm v) {
            signatureAlgorithm = v;
            return this;
        }

        /** The ACSP_V2 payload hash. null = SHA-512 (as in the Smart-ID v3 example). */
        public Builder hashAlgorithm(HashAlgorithm v) {
            hashAlgorithm = v;
            return this;
        }

        public AuthOptions build() {
            return new AuthOptions(this);
        }
    }
}
