package mn.eidmongolia.eid;

/**
 * POST /pdf/signatures result (Go {@code PDFSignatureRegistered}, TS {@code RegisterSignatureResult}).
 *
 * @param registeredAt RFC 3339 (+08)
 * @param created true: 201 (newly registered); false: 200 (idempotent repeat of the same body, the original answer)
 */
public record PdfSignatureRegistered(String docId, int revIndex, String registeredAt, String verifyUrl, boolean created) {
}
