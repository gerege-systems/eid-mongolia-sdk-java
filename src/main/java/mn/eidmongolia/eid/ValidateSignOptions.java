package mn.eidmongolia.eid;

import java.security.cert.X509Certificate;

/** Extra checks of {@link ResponseValidator#validateSign} (Go {@code ValidateSignOptions}, TS {@code ValidateSignOptions}). */
public final class ValidateSignOptions {
    /** No extra checks. */
    public static final ValidateSignOptions NONE = builder().build();

    final FlowType expectedFlowType;
    final SignatureAlgorithm expectedAlgorithm;
    final X509Certificate expectedCertificate;

    private ValidateSignOptions(Builder b) {
        this.expectedFlowType = b.expectedFlowType;
        this.expectedAlgorithm = b.expectedAlgorithm;
        this.expectedCertificate = b.expectedCertificate;
    }

    public static Builder builder() {
        return new Builder();
    }

    public FlowType expectedFlowType() {
        return expectedFlowType;
    }

    public SignatureAlgorithm expectedAlgorithm() {
        return expectedAlgorithm;
    }

    public X509Certificate expectedCertificate() {
        return expectedCertificate;
    }

    /** {@link ValidateSignOptions} fields. */
    public static final class Builder {
        private FlowType expectedFlowType;
        private SignatureAlgorithm expectedAlgorithm;
        private X509Certificate expectedCertificate;

        private Builder() {
        }

        /**
         * The flow the RP started (device link: QR / WEB2APP / APP2APP; push → NOTIFICATION). When given, the response's
         * flowType must be EXACTLY it. RAW_DIGEST_SIGNATURE does not sign the flowType (only the digest) — this is a
         * consistency check of the RP-API response, not a cryptographic guarantee.
         */
        public Builder expectedFlowType(FlowType v) {
            expectedFlowType = v;
            return this;
        }

        /**
         * The signatureAlgorithm sent in the request ({@link SignContext#signatureAlgorithm()}). When given, the response's
         * RSA algorithm must be EXACTLY it (rsassa-pss requested, sha256WithRSAEncryption answered → rejected, and vice
         * versa). The CA's legacy threshold-ECDSA credential answers ecdsa-with-SHA256 whatever was requested — accepted
         * only with an EC P-256 certificate and SHA-256. null = the RSA algorithm is not pinned (older behaviour).
         */
        public Builder expectedAlgorithm(SignatureAlgorithm v) {
            expectedAlgorithm = v;
            return this;
        }

        /**
         * The certificate known in advance (certificate choice: {@link Signer#certificate()}). When given, the response's
         * certificate must be byte-identical — another device / certificate (a citizen with several phones) is rejected.
         */
        public Builder expectedCertificate(X509Certificate v) {
            expectedCertificate = v;
            return this;
        }

        public ValidateSignOptions build() {
            return new ValidateSignOptions(this);
        }
    }
}
