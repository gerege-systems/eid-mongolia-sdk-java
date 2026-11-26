package mn.eidmongolia.eid.pades.validate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import mn.eidmongolia.eid.pades.EidPadesTransport;

/**
 * Options of {@code EidPades.validatePdf} (Go {@code pades.ValidateOptions}, TS {@code ValidatePdfOptions}). Immutable;
 * {@link #DEFAULT} = the embedded Mongolian National Root CA, now, online revocation through the default HTTP client.
 */
public final class ValidatePdfOptions {
    /** Embedded roots, now, online revocation. */
    public static final ValidatePdfOptions DEFAULT = builder().build();

    final List<byte[]> roots;
    final List<byte[]> intermediates;
    final List<byte[]> issuers;
    final Instant time;
    final boolean offline;
    final EidPadesTransport transport;

    private ValidatePdfOptions(Builder b) {
        roots = copy(b.roots);
        intermediates = copy(b.intermediates);
        issuers = copy(b.issuers);
        time = b.time;
        offline = b.offline;
        transport = b.transport;
    }

    private static List<byte[]> copy(List<byte[]> l) {
        List<byte[]> out = new ArrayList<>();
        for (byte[] d : l) out.add(d == null ? null : d.clone());
        return Collections.unmodifiableList(out);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private final List<byte[]> roots = new ArrayList<>();
        private final List<byte[]> intermediates = new ArrayList<>();
        private final List<byte[]> issuers = new ArrayList<>();
        private Instant time;
        private boolean offline;
        private EidPadesTransport transport;

        private Builder() {
        }

        /** Trust anchors (DER). None = the embedded Mongolian National Root CA (01). */
        public Builder roots(List<byte[]> der) {
            roots.clear();
            if (der != null) roots.addAll(der);
            return this;
        }

        /** Extra intermediate CAs (DER), besides the embedded 02–05. */
        public Builder intermediates(List<byte[]> der) {
            intermediates.clear();
            if (der != null) intermediates.addAll(der);
            return this;
        }

        /** Extra CAs treated as eID issuers (DER), besides the embedded 04/05 (tests). */
        public Builder issuers(List<byte[]> der) {
            issuers.clear();
            if (der != null) issuers.addAll(der);
            return this;
        }

        /** Validation time for signatures without a trusted timestamp, and "now" for revocation freshness; default now. */
        public Builder time(Instant t) {
            time = t;
            return this;
        }

        /**
         * No network: revocation only from the document's DSS (OCSP/CRL). Default false — the certificate's AIA OCSP (else
         * CDP CRL) for the current status, falling back to the DSS. Only certificate serials go over the network, never
         * the document.
         */
        public Builder offline(boolean v) {
            offline = v;
            return this;
        }

        /** HTTP for online OCSP/CRL (proxy, sandbox, tests); default the SDK's JDK HTTP client. */
        public Builder transport(EidPadesTransport t) {
            transport = t;
            return this;
        }

        public ValidatePdfOptions build() {
            return new ValidatePdfOptions(this);
        }
    }
}
