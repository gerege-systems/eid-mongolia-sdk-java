package mn.eidmongolia.eid;

/**
 * Optional settings of a signature session (Go {@code SignOptions}, TS {@code SignOptions}). Immutable; create with
 * {@link #builder()}. Unset values take the defaults.
 */
public final class SignOptions {
    static final SignOptions DEFAULTS = builder().build();

    final CertificateLevel certificateLevel;
    final String callbackUrl;
    final HashAlgorithm hashAlgorithm;
    final SignatureAlgorithm signatureAlgorithm;
    final String onBehalfOf;
    final String fileName;

    private SignOptions(Builder b) {
        certificateLevel = b.certificateLevel;
        callbackUrl = b.callbackUrl == null ? "" : b.callbackUrl.strip();
        hashAlgorithm = b.hashAlgorithm;
        signatureAlgorithm = b.signatureAlgorithm;
        onBehalfOf = b.onBehalfOf == null ? "" : b.onBehalfOf.strip();
        fileName = b.fileName == null ? "" : b.fileName.strip();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private CertificateLevel certificateLevel;
        private String callbackUrl;
        private HashAlgorithm hashAlgorithm;
        private SignatureAlgorithm signatureAlgorithm;
        private String onBehalfOf;
        private String fileName;

        private Builder() {
        }

        /** null = the client's default. */
        public Builder certificateLevel(CertificateLevel v) {
            certificateLevel = v;
            return this;
        }

        /**
         * Same-device return https URL (initialCallbackUrl). Device-link Web2App/App2App links are valid only for a session
         * started with it; the host must be in the RP's callbackHosts. Trimmed.
         */
        public Builder callbackUrl(String v) {
            callbackUrl = v;
            return this;
        }

        /** The digest's hash. null = SHA-256; the digest length must be its hLen. */
        public Builder hashAlgorithm(HashAlgorithm v) {
            hashAlgorithm = v;
            return this;
        }

        /**
         * null = rsassa-pss (PKCS#1 v1.5 is deprecated); for {@link SignService#digestForSigner} /
         * {@link SignService#deviceLinkForSigner} null = sha256WithRSAEncryption (PAdES / CMS).
         */
        public Builder signatureAlgorithm(SignatureAlgorithm v) {
            signatureAlgorithm = v;
            return this;
        }

        /**
         * On behalf of an organisation (NTRMN-&lt;register&gt;). The signature uses the citizen's PIN2 certificate; the
         * organisation is NOT in the digest. Refusals: {@link EidErrorCodes#ON_BEHALF}. Trimmed.
         */
        public Builder onBehalfOf(String v) {
            onBehalfOf = v;
            return this;
        }

        /**
         * The signed document's name, shown on the CA /verify page and the citizen's history. Optional (the CA guesses
         * from the interaction text). Trimmed; "" = not sent.
         */
        public Builder fileName(String v) {
            fileName = v;
            return this;
        }

        public SignOptions build() {
            return new SignOptions(this);
        }
    }
}
