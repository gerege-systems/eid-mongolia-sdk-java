package mn.eidmongolia.eid;

import java.util.List;

/**
 * Discovery's share block (Go {@code ShareInfo}); absent (older CA) → enabled false.
 *
 * @param enabled mail service and validator configured; false → share answers 503 MAIL_UNAVAILABLE /
 *     VALIDATOR_UNAVAILABLE (older CA: SHARE_DISABLED)
 * @param languages e-mail languages (mn, en)
 * @param permission the RP permission needed (SIGN)
 * @param rawJson the block's raw JSON ("" when absent)
 */
public record ShareInfo(boolean enabled, String endpoint, List<Format> formats, List<String> languages, int maxFileBytes,
    int maxFilenameChars, int maxMessageChars, int maxRecipients, int maxSubjectChars, String permission, Quota quota,
    boolean requiresValidSignature, String rawJson) {

    /** A supported format (pdf for now; Go {@code ShareFormat}). */
    public record Format(String name, String extension, String mime) {
    }

    /** Per RP per hour / day (requests), per recipient per day (e-mails, per RP) (Go {@code ShareQuota}). */
    public record Quota(int perRpHour, int perRpDay, int perRecipientDay) {
    }
}
