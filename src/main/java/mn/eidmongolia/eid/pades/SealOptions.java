package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;

/**
 * {@link EidPades#sealPdf} options (Go {@code pades.SealOptions}). No verification page is added (the seal registration
 * keeps page-less documents — CA V158); register the sealed PDF with {@link Completed#sealRegistration()} and
 * {@code EidClient.seal().registerSealedPdf}.
 *
 * <p><b>The seal stamp is visible by default</b> (APPEARANCE_SPEC.md §6, golden v12): the organisation seal stamp — no QR
 * or link — on the last page that is not an eID verify page, bottom-right, moved to a free spot when it would cover
 * content (PLACEMENT_SPEC.md):
 * <ul>
 *   <li>{@link #invisible()} true → no stamp, byte-for-byte Go {@code SealOptions{Invisible: true}} (and the 0.2.0 output);</li>
 *   <li>{@link #appearance()} given → used as is (page, x, y, width, height, lang, exact; as a citizen stamp); invalid →
 *       REQUEST_INVALID;</li>
 *   <li>neither → automatic (§6.4): up to {@link EidPades#SEAL_STAMP_WIDTH} × {@link EidPades#SEAL_STAMP_HEIGHT} pt,
 *       {@link EidPades#SEAL_STAMP_MARGIN} pt from the bottom-right corner (fitted on small pages), not exact; when it
 *       cannot be drawn (page unreadable or too small, the text does not fit, or its fonts push the output over the size
 *       limit) the seal is written invisible instead.</li>
 * </ul>
 * The result's position is {@link Completed#placement()} (null when invisible).
 *
 * <p>{@link #qr()} (opt-in, APPEARANCE_SPEC.md §6.5, golden v13): the stamp carries a QR to {@code /verify/<docId>/<revIndex>};
 * the {@link Sealer} must be a {@link DocumentSealer} (the position is reserved while sealing) and the result must be
 * registered within 7 days. The default (false) output is unchanged byte for byte.
 *
 * <p><b>Behaviour change from 0.2.0:</b> 0.2.0 required {@code invisible(true)} and failed with REQUEST_INVALID otherwise;
 * the default is now the visible stamp, as in Go/.NET. Validators released before the seal stamp (older CA / TS SDK)
 * report the earlier signatures as modified — keep {@code invisible(true)} until they are updated.
 */
public final class SealOptions {
    private final String reason;
    private final String signerName;
    private final Date signingTime;
    private final List<byte[]> chain;
    private final CompleteOptions complete;
    private final boolean invisible;
    private final SignatureAppearance appearance;
    private final boolean qr;
    private final String docId;
    private final String fileName;

    private SealOptions(Builder b) {
        reason = b.reason;
        signerName = b.signerName;
        signingTime = b.signingTime == null ? null : new Date(b.signingTime.getTime());
        List<byte[]> c = new ArrayList<>();
        if (b.chain != null) for (byte[] x : b.chain) c.add(x.clone());
        chain = Collections.unmodifiableList(c);
        complete = b.complete == null ? CompleteOptions.DEFAULT : b.complete;
        invisible = b.invisible;
        appearance = b.appearance;
        qr = b.qr;
        docId = b.docId;
        fileName = b.fileName;
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

    /** No stamp (the 0.2.0 / Go v0.29 SealPDF output); {@link #appearance()} is then ignored. Default false. */
    public boolean invisible() {
        return invisible;
    }

    /** The stamp's position (same values as a citizen stamp); null = automatic (see the class comment). */
    public SignatureAppearance appearance() {
        return appearance;
    }

    /**
     * Draw the seal stamp WITH a QR (APPEARANCE_SPEC.md §6.5, golden v13): QR = {@code /verify/<docId>/<revIndex>}. The
     * {@link Sealer} must be a {@link DocumentSealer} (docId / revIndex are reserved while sealing — CA V158), else
     * REQUEST_INVALID; with {@link #invisible()} → REQUEST_INVALID. The QR promises a registration: send
     * {@link Completed#sealRegistration()} with {@code EidClient.seal().registerSealedPdf} within 7 days. When the automatic
     * stamp does not fit the page (a QR stamp needs ≥ 45 pt height) the seal is invisible and nothing is reserved
     * ({@link Completed#placement()} null). Default false — the QR-less stamp (§6.2), byte-identical to golden v12.
     */
    public boolean qr() {
        return qr;
    }

    /**
     * The document's UUID (lowercase; {@link PrepareOptions#docId()}, APPEARANCE_SPEC.md §6.6): an unsigned document → random
     * when null; a signed one → the docId of its verify page / QR seal stamp when present (a different value →
     * REQUEST_INVALID), else this value — null then gives {@link Completed#docId()} null and no registration (with
     * {@link #qr()} → REQUEST_INVALID). Written into the stamp only with the QR.
     */
    public String docId() {
        return docId;
    }

    /** The name in the CA registry (/verify; optional, NFC, ≤ 120 characters — else REQUEST_INVALID). Not written to the PDF. */
    public String fileName() {
        return fileName;
    }

    public static final class Builder {
        private String reason;
        private String signerName;
        private Date signingTime;
        private List<byte[]> chain;
        private CompleteOptions complete;
        private boolean invisible;
        private SignatureAppearance appearance;
        private boolean qr;
        private String docId;
        private String fileName;

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

        public Builder appearance(SignatureAppearance v) {
            appearance = v;
            return this;
        }

        /** See {@link SealOptions#qr()}. */
        public Builder qr(boolean v) {
            qr = v;
            return this;
        }

        /** See {@link SealOptions#docId()}. */
        public Builder docId(String v) {
            docId = v;
            return this;
        }

        /** See {@link SealOptions#fileName()}. */
        public Builder fileName(String v) {
            fileName = v;
            return this;
        }

        public SealOptions build() {
            return new SealOptions(this);
        }
    }
}
