package mn.eidmongolia.eid.pades;

/**
 * Stable error codes (Go {@code pades/errors.go}). {@link #code()} is the SAME string on Go/.NET/Swift/Kotlin — branch on
 * it, never on the message. Messages never contain the citizen's name (certificates are named by serial).
 */
public class EidPadesException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final String code;

    EidPadesException(String code, String message) {
        super(message);
        this.code = code;
    }

    public String code() {
        return code;
    }

    /** TSA_UNAVAILABLE / LTV_UNAVAILABLE (temporary — call complete again with the same state + signature), except a revoked certificate. */
    public boolean retryable() {
        return this instanceof TsaUnavailable || (this instanceof LtvUnavailable && !((LtvUnavailable) this).certificateRevoked());
    }

    public static final class PdfInvalid extends EidPadesException {
        PdfInvalid(String m) {
            super("PDF_INVALID", m);
        }
    }

    public static final class PdfEncrypted extends EidPadesException {
        PdfEncrypted(String m) {
            super("PDF_ENCRYPTED", m);
        }
    }

    /** DocMDP P=1 — the document allows no further signature. */
    public static final class PdfLocked extends EidPadesException {
        PdfLocked(String m) {
            super("PDF_LOCKED", m);
        }
    }

    public static final class PdfTooLarge extends EidPadesException {
        PdfTooLarge(String m) {
            super("PDF_TOO_LARGE", m);
        }
    }

    /** The signature limit (16) is reached. */
    public static final class PdfTooManySignatures extends EidPadesException {
        PdfTooManySignatures(String m) {
            super("PDF_TOO_MANY_SIGNATURES", m);
        }
    }

    /** A prior signature is broken — nothing is signed on top of it. */
    public static final class PdfPriorSignatureInvalid extends EidPadesException {
        PdfPriorSignatureInvalid(String m) {
            super("PDF_PRIOR_SIGNATURE_INVALID", m);
        }
    }

    /** A prior signature is not a valid eID B-LT signature. */
    public static final class PdfForeignSignature extends EidPadesException {
        PdfForeignSignature(String m) {
            super("PDF_FOREIGN_SIGNATURE", m);
        }
    }

    /** signerCert / chain does not parse or the key type is unsupported. */
    public static final class SignerInvalid extends EidPadesException {
        SignerInvalid(String m) {
            super("SIGNER_INVALID", m);
        }
    }

    /** Invalid options (docId, lang, fileName, appearance, claimedRole, registration medium…). */
    public static final class RequestInvalid extends EidPadesException {
        RequestInvalid(String m) {
            super("REQUEST_INVALID", m);
        }
    }

    /** The signature does not verify over the DTBS with the signer certificate. */
    public static final class SignatureInvalid extends EidPadesException {
        SignatureInvalid(String m) {
            super("SIGNATURE_INVALID", m);
        }
    }

    /** The TSA did not answer / the token is invalid — retry with the same state. */
    public static final class TsaUnavailable extends EidPadesException {
        TsaUnavailable(String m) {
            super("TSA_UNAVAILABLE", m);
        }
    }

    /**
     * OCSP/CRL could not be collected — retry with the same state. {@link #certificateRevoked()} = a chain certificate is
     * revoked by its issuer-signed OCSP/CRL (final, do not retry).
     */
    public static final class LtvUnavailable extends EidPadesException {
        private final boolean certificateRevoked;

        LtvUnavailable(String m, boolean certificateRevoked) {
            super("LTV_UNAVAILABLE", m);
            this.certificateRevoked = certificateRevoked;
        }

        public boolean certificateRevoked() {
            return certificateRevoked;
        }
    }

    public static final class SelfValidationFailed extends EidPadesException {
        SelfValidationFailed(String m) {
            super("SELF_VALIDATION_FAILED", m);
        }
    }

    public static final class PlaceholderOverflow extends EidPadesException {
        PlaceholderOverflow(String m) {
            super("PLACEHOLDER_OVERFLOW", m);
        }
    }

    public static final class StateInvalid extends EidPadesException {
        StateInvalid(String m) {
            super("STATE_INVALID", m);
        }
    }

    /** An internal SDK error. */
    public static final class Internal extends EidPadesException {
        Internal(String m) {
            super("INTERNAL", m);
        }
    }
}
