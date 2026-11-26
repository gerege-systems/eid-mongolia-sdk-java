package mn.eidmongolia.eid;

/**
 * POST /share 200 (Go {@code ShareResult}).
 *
 * @param sent e-mails sent
 * @param sha256 the file's SHA-256 (hex)
 * @param signatures valid eID signatures in the file
 * @param docId the CA registry document ID when registered (the e-mail then carries a verify link); else ""
 * @param rawJson the server's raw JSON
 */
public record ShareResult(int sent, String sha256, int signatures, String docId, String rawJson) {
}
