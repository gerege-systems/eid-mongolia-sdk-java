package mn.eidmongolia.eid;

/** Optional settings of a certificate-choice session (Go {@code CertChoiceOptions}). Create with {@link #builder()}. */
public final class CertChoiceOptions {
    static final CertChoiceOptions DEFAULTS = builder().build();

    final CertificateLevel certificateLevel;
    final String callbackUrl;

    private CertChoiceOptions(Builder b) {
        certificateLevel = b.certificateLevel;
        callbackUrl = b.callbackUrl == null ? "" : b.callbackUrl.strip();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private CertificateLevel certificateLevel;
        private String callbackUrl;

        private Builder() {
        }

        /** null = the client's default. */
        public Builder certificateLevel(CertificateLevel v) {
            certificateLevel = v;
            return this;
        }

        /**
         * ONLY {@link SignService#certificateChoiceDeviceLink}: the same-device return https URL (initialCallbackUrl).
         * With it Web2App/App2App links work and the phone opens the URL only after the linked SIGN finished (query: the
         * RP's own parameters + sessionSecretDigest + sessionId — {@link EidCrypto#sessionSecretDigest}). The host must be
         * in the RP's callbackHosts (else the CA drops it and the session is QR-only).
         * {@link SignService#certificateChoiceByEtsi} never sends it. Trimmed.
         */
        public Builder callbackUrl(String v) {
            callbackUrl = v;
            return this;
        }

        public CertChoiceOptions build() {
            return new CertChoiceOptions(this);
        }
    }
}
