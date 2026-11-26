package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * {@link EidPades#prepare} input — Go reference {@code pades.PrepareOptions} (Android/iOS {@code PrepareOptions} 1:1).
 * Immutable; build with {@link #builder(byte[])}.
 *
 * <ul>
 *   <li>{@code signerCert} — citizen SIGN certificate DER (signingCertificateV2)</li>
 *   <li>{@code chain} — issuer chain DER (04, 03, 02); empty → built from the embedded eID chain</li>
 *   <li>{@code signerName} — {@code /Name}; null/blank → certificate GIVENNAME SURNAME (else CN)</li>
 *   <li>{@code reason} — {@code /Reason} (≤ 127 UTF-16 units, else omitted)</li>
 *   <li>{@code claimedRole} — CA representation response {@code claimedRole} (onBehalfOf) → signer-attributes-v2</li>
 *   <li>{@code signingTime} — {@code /M}; null → now. Always written at +08:00</li>
 *   <li>{@code docId} — verify page / QR UUID (lowercase). Unsigned document: this value, else a random one. Signed
 *       document (APPEARANCE_SPEC.md §6.6, golden v13): (1) the verify-page link's docId, else (2) the docId of the earliest
 *       organisation e-Seal stamp carrying an {@code /EIDVerify} marker, else (3) this value, else none — a random docId is
 *       never generated for a signed document. A docId found by (1) or (2) that differs from this value → REQUEST_INVALID
 *       (also for an invisible signature). A stamp that draws a QR with no docId → REQUEST_INVALID.</li>
 *   <li>{@code verifyPage} — append the verification (QR) page — only for a document without signatures</li>
 *   <li>{@code fileName} — name shown on the page (required with verifyPage; NFC, ≤ 120 characters)</li>
 *   <li>{@code lang} — page language "mn" | "en"; null/empty → "mn"</li>
 *   <li>{@code appearance} — visible signature (APPEARANCE_SPEC.md); null → invisible. The stamp variant follows the
 *       signer certificate only (§6.1): an organisation e-Seal certificate (KeyUsage nonRepudiation without
 *       digitalSignature, no EKU) draws the QR-less organisation seal stamp (§6.2, no role line), any other certificate the
 *       citizen stamp with QR (§3)</li>
 *   <li>{@code verifyPagePosition} — "last" (default; also null/empty) or "first" (the verification page becomes page 1);
 *       {@link SignatureAppearance#page()}, {@code suggestPlacement} and {@link Placement#page()} always count the input
 *       PDF's pages (PAGE_SPEC §8a, PLACEMENT_SPEC §1b). Other values → REQUEST_INVALID.</li>
 * </ul>
 */
public final class PrepareOptions {
    private final byte[] signerCert;
    private final List<byte[]> chain;
    private final String signerName;
    private final String reason;
    private final String claimedRole;
    private final Date signingTime;
    private final String docId;
    private final boolean verifyPage;
    private final String fileName;
    private final String lang;
    private final SignatureAppearance appearance;
    private final String verifyPagePosition;
    // APPEARANCE_SPEC.md §6.5 QR seal stamp: NOT a public prepare option (Go PrepareOptions.sealQR is unexported) — the QR
    // promises a registration, so only sealPdf (SealOptions.qr — docId/revIndex reservation + sealRegistration) and the
    // golden tests set it.
    private final boolean sealQr;

    private PrepareOptions(Builder b) {
        signerCert = b.signerCert.clone();
        List<byte[]> c = new ArrayList<>();
        for (byte[] d : b.chain) c.add(d.clone());
        chain = Collections.unmodifiableList(c);
        signerName = b.signerName;
        reason = b.reason;
        claimedRole = b.claimedRole;
        signingTime = b.signingTime == null ? null : new Date(b.signingTime.getTime());
        docId = b.docId;
        verifyPage = b.verifyPage;
        fileName = b.fileName;
        lang = b.lang;
        appearance = b.appearance;
        verifyPagePosition = b.verifyPagePosition;
        sealQr = b.sealQr;
    }

    /** @param signerCert citizen SIGN certificate, DER */
    public static Builder builder(byte[] signerCert) {
        return new Builder(signerCert);
    }

    public byte[] signerCert() {
        return signerCert.clone();
    }

    byte[] signerCertRaw() {
        return signerCert;
    }

    public List<byte[]> chain() {
        return chain;
    }

    public String signerName() {
        return signerName;
    }

    public String reason() {
        return reason;
    }

    public String claimedRole() {
        return claimedRole;
    }

    public Date signingTime() {
        return signingTime == null ? null : new Date(signingTime.getTime());
    }

    public String docId() {
        return docId;
    }

    public boolean verifyPage() {
        return verifyPage;
    }

    public String fileName() {
        return fileName;
    }

    public String lang() {
        return lang;
    }

    public SignatureAppearance appearance() {
        return appearance;
    }

    public String verifyPagePosition() {
        return verifyPagePosition;
    }

    boolean sealQr() {
        return sealQr;
    }

    /** {@link PrepareOptions} builder (not thread-safe; the built options are immutable). */
    public static final class Builder {
        private final byte[] signerCert;
        private List<byte[]> chain = Collections.emptyList();
        private String signerName;
        private String reason;
        private String claimedRole;
        private Date signingTime;
        private String docId;
        private boolean verifyPage;
        private String fileName;
        private String lang;
        private SignatureAppearance appearance;
        private String verifyPagePosition;
        private boolean sealQr;

        private Builder(byte[] signerCert) {
            this.signerCert = Objects.requireNonNull(signerCert, "signerCert");
        }

        public Builder chain(List<byte[]> chain) {
            this.chain = chain == null ? Collections.emptyList() : new ArrayList<>(chain);
            return this;
        }

        public Builder signerName(String v) {
            signerName = v;
            return this;
        }

        public Builder reason(String v) {
            reason = v;
            return this;
        }

        public Builder claimedRole(String v) {
            claimedRole = v;
            return this;
        }

        public Builder signingTime(Date v) {
            signingTime = v;
            return this;
        }

        public Builder docId(String v) {
            docId = v;
            return this;
        }

        public Builder verifyPage(boolean v) {
            verifyPage = v;
            return this;
        }

        public Builder fileName(String v) {
            fileName = v;
            return this;
        }

        public Builder lang(String v) {
            lang = v;
            return this;
        }

        public Builder appearance(SignatureAppearance v) {
            appearance = v;
            return this;
        }

        public Builder verifyPagePosition(String v) {
            verifyPagePosition = v;
            return this;
        }

        /** Package-private (tests): the e-Seal stamp with QR (APPEARANCE_SPEC.md §6.5). */
        Builder sealQr(boolean v) {
            sealQr = v;
            return this;
        }

        public PrepareOptions build() {
            return new PrepareOptions(this);
        }
    }
}
