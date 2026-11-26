package mn.eidmongolia.eid;

import java.time.Duration;
import java.util.List;

/**
 * The validator's trust configuration (Go {@code TrustConfig}, TS {@code TrustConfig}). Production needs
 * {@link Builder#trustAnchorsPem} — without an anchor every validation fails ({@link ValidationReasons#TRUST_NO_ANCHOR}).
 *
 * <pre>{@code
 * TrustConfig trust = TrustConfig.builder().trustAnchorsPem(Roots.NATIONAL_ROOT_CA_PEM).build();
 * }</pre>
 */
public final class TrustConfig {
    final List<String> trustAnchorsPem;
    final List<String> intermediatesPem;
    final CertificateLevel requiredLevel;
    final Duration clockSkew;
    final boolean allowUntrusted;
    final RevocationChecker revocation;
    final RevocationMode revocationMode;
    final List<String> allowedIssuerSkis;
    final boolean allowAnyIssuer;
    final boolean skipKeyUsageCheck;
    final String schemeName;

    private TrustConfig(Builder b) {
        this.trustAnchorsPem = b.trustAnchorsPem == null ? List.of() : List.copyOf(b.trustAnchorsPem);
        this.intermediatesPem = b.intermediatesPem == null ? null : List.copyOf(b.intermediatesPem);
        this.requiredLevel = b.requiredLevel;
        this.clockSkew = b.clockSkew;
        this.allowUntrusted = b.allowUntrusted;
        this.revocation = b.revocation;
        this.revocationMode = b.revocationMode;
        this.allowedIssuerSkis = b.allowedIssuerSkis == null ? List.of() : List.copyOf(b.allowedIssuerSkis);
        this.allowAnyIssuer = b.allowAnyIssuer;
        this.skipKeyUsageCheck = b.skipKeyUsageCheck;
        this.schemeName = b.schemeName;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** {@link TrustConfig} fields; unset values take the defaults. */
    public static final class Builder {
        private List<String> trustAnchorsPem;
        private List<String> intermediatesPem;
        private CertificateLevel requiredLevel;
        private Duration clockSkew;
        private boolean allowUntrusted;
        private RevocationChecker revocation;
        private RevocationMode revocationMode;
        private List<String> allowedIssuerSkis;
        private boolean allowAnyIssuer;
        private boolean skipKeyUsageCheck;
        private String schemeName;

        private Builder() {
        }

        /**
         * Trust anchor (root CA) PEMs, e.g. {@link Roots#NATIONAL_ROOT_CA_PEM}; a string may hold several certificates.
         * REQUIRED in production — empty fails every validation (only {@link #allowUntrusted} skips the chain).
         */
        public Builder trustAnchorsPem(String... pems) {
            trustAnchorsPem = List.of(pems);
            return this;
        }

        public Builder trustAnchorsPem(List<String> pems) {
            trustAnchorsPem = pems;
            return this;
        }

        /**
         * Intermediate CA PEMs (between leaf and root). Not set = {@link Roots#CITIZEN_INTERMEDIATES_PEM} (02 → 03 → 04);
         * set (even empty) = exactly this list.
         */
        public Builder intermediatesPem(List<String> pems) {
            intermediatesPem = pems;
            return this;
        }

        /** The required certLevel; null = QUALIFIED. Higher levels are accepted (QSCD ⊇ QUALIFIED). */
        public Builder requiredLevel(CertificateLevel v) {
            requiredLevel = v;
            return this;
        }

        /** Clock tolerance for the certificate validity check; null = 0. */
        public Builder clockSkew(Duration v) {
            clockSkew = v;
            return this;
        }

        /** Continue without a trust anchor (no chain check). DEV / TEST ONLY. */
        public Builder allowUntrusted(boolean v) {
            allowUntrusted = v;
            return this;
        }

        /**
         * The revocation checker for {@link ResponseValidator#checkRevocation} (e.g. {@link OcspRevocationChecker});
         * null = no check (for QUALIFIED non-repudiation that is the RP's duty).
         */
        public Builder revocation(RevocationChecker v) {
            revocation = v;
            return this;
        }

        /** null = {@link RevocationMode#HARD_FAIL}. */
        public Builder revocationMode(RevocationMode v) {
            revocationMode = v;
            return this;
        }

        /**
         * Subject Key Identifiers (hex, ":" allowed) of the CAs allowed to issue citizen certificates directly. Empty =
         * {@link Roots#CITIZEN_ISSUING_CA_SKI} when an anchor is configured (protects against another CA under the same
         * root, e.g. the organisation Issuing CA 05); given = checked always.
         */
        public Builder allowedIssuerSkis(List<String> v) {
            allowedIssuerSkis = v;
            return this;
        }

        /**
         * true switches the default issuer allowlist off — any CA chaining to the anchor (an explicit
         * {@link #allowedIssuerSkis} is still checked). Tests / other Issuing CAs only.
         */
        public Builder allowAnyIssuer(boolean v) {
            allowAnyIssuer = v;
            return this;
        }

        /**
         * true skips the certificate purpose check (auth → KeyUsage digitalSignature + EKU clientAuth; sign → KeyUsage
         * nonRepudiation) — not recommended: an authentication (PIN1) key's signature would pass validateSign. Go
         * {@code SkipKeyUsageCheck}, TS {@code checkKeyUsage: false}.
         */
        public Builder skipKeyUsageCheck(boolean v) {
            skipKeyUsageCheck = v;
            return this;
        }

        /** The ACSP_V2 scheme name (the CA's capabilities.acsp_scheme_name); null / "" = "smart-id". */
        public Builder schemeName(String v) {
            schemeName = v;
            return this;
        }

        public TrustConfig build() {
            return new TrustConfig(this);
        }
    }
}
