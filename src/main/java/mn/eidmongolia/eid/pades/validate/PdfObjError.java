package mn.eidmongolia.eid.pades.validate;

/** TS pdfobj.ts PdfObjError (Go errPDFSyntax / errPDFLimit / errNotSignatureOnly): "not accepted". */
final class PdfObjError extends RuntimeException {
    private static final long serialVersionUID = 1L;

    PdfObjError(String msg) {
        super(msg, null, false, false);
    }

    static PdfObjError syntax() {
        return new PdfObjError("validate: PDF structure not recognized");
    }

    static PdfObjError limit() {
        return new PdfObjError("validate: PDF analysis limit exceeded");
    }

    static PdfObjError notSignatureOnly() {
        return new PdfObjError("validate: change after signing is not on the allow-list");
    }
}
