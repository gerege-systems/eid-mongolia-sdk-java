package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * {@link EidPades#sealPdf} options (Go {@code pades.SealOptions}). No verification (QR) page is added: the seal is not
 * entered in the citizen signature registry ({@code POST /pdf/signatures}).
 *
 * <p><b>Invisible only in this release.</b> The Go reference draws a visible organisation seal stamp by default
 * (APPEARANCE_SPEC.md §6, golden v12/v13); this SDK's PAdES engine is still at golden v11, so {@link #invisible()} must
 * be true — otherwise {@code sealPdf} fails with REQUEST_INVALID before any network call (the default will become the
 * visible stamp once the golden catch-up lands; asking for invisible explicitly keeps today's output then too).
 * {@code invisible(true)} is byte-for-byte Go {@code SealOptions{Invisible: true}} (the v0.29 SealPDF output).
 */
public final class SealOptions {
    private final String reason;
    private final String signerName;
    private final Date signingTime;
    private final List<byte[]> chain;
    private final CompleteOptions complete;
    private final boolean invisible;

    private SealOptions(Builder b) {
        reason = b.reason;
        signerName = b.signerName;
        signingTime = b.signingTime == null ? null : new Date(b.signingTime.getTime());
        List<byte[]> c = new ArrayList<>();
        if (b.chain != null) for (byte[] x : b.chain) c.add(x.clone());
        chain = Collections.unmodifiableList(c);
        complete = b.complete == null ? CompleteOptions.DEFAULT : b.complete;
        invisible = b.invisible;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** /Reason (≤ 127 UTF-16 units); null = none. */
    public String reason() {
        return reason;
    }

    /** /Name; null = the certificate's CN (the organisation's name). */
    public String signerName() {
        return signerName;
    }

    /** /M; null = now. */
    public Date signingTime() {
        return signingTime == null ? null : new Date(signingTime.getTime());
    }

    /** Issuer chain DER (05, 03, 02); empty = the embedded eID chain. */
    public List<byte[]> chain() {
        List<byte[]> out = new ArrayList<>();
        for (byte[] x : chain) out.add(x.clone());
        return out;
    }

    /** TSA / OCSP / CRL settings ({@link EidPades#complete}). An RFC 3161 timestamp is REQUIRED (TSA down → TSA_UNAVAILABLE). */
    public CompleteOptions complete() {
        return complete;
    }

    /** No stamp — required in this release (see the class comment). */
    public boolean invisible() {
        return invisible;
    }

    public static final class Builder {
        private String reason;
        private String signerName;
        private Date signingTime;
        private List<byte[]> chain;
        private CompleteOptions complete;
        private boolean invisible;

        private Builder() {
        }

        public Builder reason(String v) {
            reason = v;
            return this;
        }

        public Builder signerName(String v) {
            signerName = v;
            return this;
        }

        public Builder signingTime(Date v) {
            signingTime = v;
            return this;
        }

        public Builder chain(List<byte[]> v) {
            chain = v;
            return this;
        }

        public Builder complete(CompleteOptions v) {
            complete = v;
            return this;
        }

        public Builder invisible(boolean v) {
            invisible = v;
            return this;
        }

        public SealOptions build() {
            return new SealOptions(this);
        }
    }
}
