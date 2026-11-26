package mn.eidmongolia.eid.pades.validate;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The validation report of {@code EidPades.validatePdf} — the CA's {@code /v3/validate/pdf} JSON (Go
 * {@code pades.PDFReport}, TS {@code PdfReport}) without the CA-registry fields ({@code session_id}, {@code doc_id},
 * {@code on_behalf_of_*}, {@code stamp_lookup}). {@link #toJson()} writes the same JSON the Go and TS SDKs write
 * (snake_case, Go field order, omitted optional fields).
 */
public final class PdfReport {
    String indication = "valid";
    final List<SignatureReport> signatures = new ArrayList<>();

    PdfReport() {
    }

    /** "valid" | "invalid" | "indeterminate" — the worst of the signatures. */
    public String indication() {
        return indication;
    }

    public List<SignatureReport> signatures() {
        return Collections.unmodifiableList(signatures);
    }

    public String toJson() {
        JsonOut j = new JsonOut();
        j.begin();
        j.field("indication").string(indication);
        j.field("signatures").beginArray();
        for (SignatureReport s : signatures) {
            j.element();
            s.write(j);
        }
        j.endArray();
        j.end();
        return j.toString();
    }

    @Override
    public String toString() {
        return toJson();
    }

    /** One signature (Go {@code SignatureReport}). */
    public static final class SignatureReport {
        String indication = "valid";
        final List<String> problems = new ArrayList<>();
        String signerName = "";
        String claimedName;
        String signerNameSource = "unverified";
        String reason;
        String location;
        String claimedTime;
        String signingTime;
        TimestampInfo timestamp;
        boolean coversWholeDocument;
        boolean extendedBySignaturesOnly;
        int laterSignatures;
        boolean visibleLaterSignature;
        boolean visible;
        boolean chainTrusted;
        List<String> chain = new ArrayList<>();
        CertInfo certificate;
        String civilId;
        String keyMedium = "unknown";
        List<String> claimedRoles;
        String signatureLevel;
        LtvInfo ltv;
        String certificateLevel;

        SignatureReport() {
        }

        /** "valid" | "invalid" | "indeterminate". */
        public String indication() {
            return indication;
        }

        /** Stable problem codes (integrity_failed, untrusted_chain, revoked, modified_after_signing, …). */
        public List<String> problems() {
            return Collections.unmodifiableList(problems);
        }

        public String signerName() {
            return signerName;
        }

        /** The signature dictionary's /Name, or null. */
        public String claimedName() {
            return claimedName;
        }

        /** "platform_attested" | "certificate" | "unverified". */
        public String signerNameSource() {
            return signerNameSource;
        }

        public String reason() {
            return reason;
        }

        public String location() {
            return location;
        }

        /** /M (RFC 3339), or null. */
        public String claimedTime() {
            return claimedTime;
        }

        /** The trusted RFC 3161 time (RFC 3339), or null. */
        public String signingTime() {
            return signingTime;
        }

        public TimestampInfo timestamp() {
            return timestamp;
        }

        public boolean coversWholeDocument() {
            return coversWholeDocument;
        }

        public boolean extendedBySignaturesOnly() {
            return extendedBySignaturesOnly;
        }

        public int laterSignatures() {
            return laterSignatures;
        }

        public boolean visibleLaterSignature() {
            return visibleLaterSignature;
        }

        public boolean visible() {
            return visible;
        }

        public boolean chainTrusted() {
            return chainTrusted;
        }

        /** Common names, leaf first. */
        public List<String> chain() {
            return Collections.unmodifiableList(chain);
        }

        public CertInfo certificate() {
            return certificate;
        }

        /** The civil ID from SERIALNUMBER PNOMN-…, or null. */
        public String civilId() {
            return civilId;
        }

        /** "phone" | "unknown" locally (the CA may also say token / server_software / server_hsm from its registry). */
        public String keyMedium() {
            return keyMedium;
        }

        public List<String> claimedRoles() {
            return claimedRoles == null ? null : Collections.unmodifiableList(claimedRoles);
        }

        /** PAdES-BASELINE-B / -T / -LT for ETSI.CAdES.detached, else null. */
        public String signatureLevel() {
            return signatureLevel;
        }

        public LtvInfo ltv() {
            return ltv;
        }

        /** ADVANCED / QUALIFIED / QSCD for a trusted chain, else null. */
        public String certificateLevel() {
            return certificateLevel;
        }

        void write(JsonOut j) {
            j.begin();
            j.field("indication").string(indication);
            j.field("problems").strings(problems);
            j.field("signer_name").string(signerName);
            if (claimedName != null) j.field("claimed_name").string(claimedName);
            j.field("signer_name_source").string(signerNameSource);
            if (reason != null) j.field("reason").string(reason);
            if (location != null) j.field("location").string(location);
            if (claimedTime != null) j.field("claimed_time").string(claimedTime);
            if (signingTime != null) j.field("signing_time").string(signingTime);
            if (timestamp != null) {
                j.field("timestamp").begin();
                j.field("time").string(timestamp.time);
                j.field("serial").string(timestamp.serial);
                j.field("tsa").string(timestamp.tsa);
                j.field("trusted").bool(timestamp.trusted);
                j.end();
            }
            j.field("covers_whole_document").bool(coversWholeDocument);
            j.field("extended_by_signatures_only").bool(extendedBySignaturesOnly);
            j.field("later_signatures").number(laterSignatures);
            j.field("visible_later_signature").bool(visibleLaterSignature);
            j.field("visible").bool(visible);
            j.field("chain_trusted").bool(chainTrusted);
            j.field("chain").strings(chain);
            if (certificate != null) {
                CertInfo c = certificate;
                j.field("certificate").begin();
                j.field("common_name").string(c.commonName);
                j.field("subject").string(c.subject);
                j.field("issuer").string(c.issuer);
                j.field("serial").string(c.serial);
                j.field("not_before").string(c.notBefore);
                j.field("not_after").string(c.notAfter);
                j.field("usage").string(c.usage);
                j.field("issued_by_eid").bool(c.issuedByEid);
                j.field("revocation").begin();
                j.field("status").string(c.revocation.status);
                if (c.revocation.revokedAt != null) j.field("revoked_at").string(c.revocation.revokedAt);
                j.end();
                j.end();
            }
            if (civilId != null) j.field("civil_id").string(civilId);
            j.field("key_medium").string(keyMedium);
            if (claimedRoles != null) j.field("claimed_roles").strings(claimedRoles);
            if (signatureLevel != null) j.field("signature_level").string(signatureLevel);
            if (ltv != null) {
                j.field("ltv").begin();
                j.field("complete").bool(ltv.complete);
                j.field("missing").strings(ltv.missing);
                j.end();
            }
            if (certificateLevel != null) j.field("certificate_level").string(certificateLevel);
            j.end();
        }
    }

    /** RFC 3161 signature timestamp. */
    public static final class TimestampInfo {
        String time;
        String serial;
        String tsa;
        boolean trusted;

        TimestampInfo(String time, String serial, String tsa, boolean trusted) {
            this.time = time;
            this.serial = serial;
            this.tsa = tsa;
            this.trusted = trusted;
        }

        public String time() {
            return time;
        }

        /** Upper-case hex. */
        public String serial() {
            return serial;
        }

        /** The TSA certificate's common name. */
        public String tsa() {
            return tsa;
        }

        public boolean trusted() {
            return trusted;
        }
    }

    /** The signer certificate. */
    public static final class CertInfo {
        String commonName;
        String subject;
        String issuer;
        String serial;
        String notBefore;
        String notAfter;
        String usage;
        boolean issuedByEid;
        RevocationInfo revocation;

        CertInfo() {
        }

        public String commonName() {
            return commonName;
        }

        /** Go pkix.Name.String(). */
        public String subject() {
            return subject;
        }

        public String issuer() {
            return issuer;
        }

        public String serial() {
            return serial;
        }

        public String notBefore() {
            return notBefore;
        }

        public String notAfter() {
            return notAfter;
        }

        /** "sign" | "auth" | "seal" | "document_signer" | "timestamp" | "other". */
        public String usage() {
            return usage;
        }

        public boolean issuedByEid() {
            return issuedByEid;
        }

        public RevocationInfo revocation() {
            return revocation;
        }
    }

    /** Revocation status at the validation time. */
    public static final class RevocationInfo {
        final String status;
        final String revokedAt;

        RevocationInfo(String status, String revokedAt) {
            this.status = status;
            this.revokedAt = revokedAt;
        }

        /** "good" | "revoked" | "unknown". */
        public String status() {
            return status;
        }

        public String revokedAt() {
            return revokedAt;
        }
    }

    /** LTV coverage of the DSS (every chain certificate but the roots). */
    public static final class LtvInfo {
        boolean complete;
        final List<String> missing = new ArrayList<>();

        LtvInfo() {
        }

        public boolean complete() {
            return complete;
        }

        public List<String> missing() {
            return Collections.unmodifiableList(missing);
        }
    }

    /** Go encoding/json-compatible writer (HTML-safe escapes, U+2028/2029). */
    static final class JsonOut {
        private final StringBuilder b = new StringBuilder();
        private boolean first = true;

        void begin() {
            b.append('{');
            first = true;
        }

        void end() {
            b.append('}');
            first = false;
        }

        void beginArray() {
            b.append('[');
            first = true;
        }

        void endArray() {
            b.append(']');
            first = false;
        }

        void element() {
            if (!first) b.append(',');
            first = false;
        }

        JsonOut field(String name) {
            if (!first) b.append(',');
            first = false;
            quote(name);
            b.append(':');
            return this;
        }

        void string(String s) {
            quote(s);
            first = false;
        }

        void bool(boolean v) {
            b.append(v);
            first = false;
        }

        void number(long v) {
            b.append(v);
            first = false;
        }

        void strings(List<String> l) {
            b.append('[');
            for (int i = 0; i < l.size(); i++) {
                if (i > 0) b.append(',');
                quote(l.get(i));
            }
            b.append(']');
            first = false;
        }

        private void quote(String s) {
            b.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"': b.append("\\\""); break;
                    case '\\': b.append("\\\\"); break;
                    case '\n': b.append("\\n"); break;
                    case '\r': b.append("\\r"); break;
                    case '\t': b.append("\\t"); break;
                    default:
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == ' ' || c == ' ') {
                            b.append(String.format("\\u%04x", (int) c));
                        } else {
                            b.append(c);
                        }
                }
            }
            b.append('"');
        }

        @Override
        public String toString() {
            return b.toString();
        }
    }
}
