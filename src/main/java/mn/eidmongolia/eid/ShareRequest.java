package mn.eidmongolia.eid;

import java.util.List;

/**
 * {@link EidClient#share} input (Go {@code ShareRequest}). Limits: discovery's share block ({@link EidClient#shareInfo}).
 *
 * @param file the signed file (PDF only for now), ≤ 3 080 192 bytes
 * @param filename the attachment name (≤ 120 characters); the extension must match the format (.pdf) or 415. null / "" =
 *     "document.pdf"
 * @param to 1–5 recipients (one e-mail each); duplicates → 400 RECIPIENT_DUPLICATE
 * @param subject ≤ 150; the CA always prefixes «‹RP name›: …»
 * @param message the sender's note (≤ 1000)
 * @param lang "mn" (default, null / "") | "en"
 */
public record ShareRequest(byte[] file, String filename, List<String> to, String subject, String message, String lang) {
    /** 422 FILE_NOT_SIGNED reason: the file has no electronic signature. */
    public static final String REASON_NO_SIGNATURE = "no_signature";
    /** 422 reason: damaged / modified / revoked / too many. */
    public static final String REASON_INVALID = "invalid";
    /** 422 reason: not chained to eID's trusted roots, or a non-eID visible signature. */
    public static final String REASON_UNTRUSTED = "untrusted";
    /** 502 MAIL_FAILED recipient state. */
    public static final String RECIPIENT_SENT = "sent";
    public static final String RECIPIENT_FAILED = "failed";

    public ShareRequest {
        file = file == null ? new byte[0] : file.clone();
        to = to == null ? List.of() : List.copyOf(to);
    }

    @Override
    public byte[] file() {
        return file.clone();
    }
}
