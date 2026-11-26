package mn.eidmongolia.eid.pades.validate;

/**
 * A document {@code EidPades.validatePdf} cannot validate at all (TS {@code ValidatePdfError}, Go sentinel errors). Every
 * per-signature problem is in the {@link PdfReport} instead.
 */
public final class ValidatePdfException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    /** Larger than 10 MiB. */
    public static final String PDF_TOO_LARGE = "PDF_TOO_LARGE";
    /** Not a PDF, or a structure the parser refuses (nesting, limits). */
    public static final String PDF_INVALID = "PDF_INVALID";
    /** Has /Encrypt (any cipher, even an empty user password). */
    public static final String PDF_ENCRYPTED = "PDF_ENCRYPTED";
    public static final String PDF_NO_SIGNATURE = "PDF_NO_SIGNATURE";
    /** More than 16 signatures. */
    public static final String PDF_TOO_MANY_SIGNATURES = "PDF_TOO_MANY_SIGNATURES";
    /** An option does not parse (a roots / intermediates / issuers certificate). */
    public static final String REQUEST_INVALID = "REQUEST_INVALID";

    private final String code;

    ValidatePdfException(String code, String message) {
        super(message);
        this.code = code;
    }

    /** One of the constants above. */
    public String code() {
        return code;
    }
}
