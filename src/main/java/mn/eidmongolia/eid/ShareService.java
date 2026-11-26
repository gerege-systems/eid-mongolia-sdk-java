package mn.eidmongolia.eid;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * POST /share and discovery's share block (Go share.go, TS share.ts) — reached through {@link EidClient#share} /
 * {@link EidClient#shareInfo}. The CA does not keep the file: it checks for a valid eID signature, hands it to the mail
 * service and drops it. SIGN permission.
 */
final class ShareService {
    /** The CA sends to every recipient within 120 s; nginx allows 150 s. */
    static final Duration TIMEOUT = Duration.ofSeconds(150);
    /** The multipart members (CA parseShareRequest; unknown fields → 400) — the contract test compares discovery. */
    static final List<String> FORM_FIELDS = List.of("file", "filename", "to", "subject", "message", "lang");

    private static final SecureRandom RANDOM = new SecureRandom();
    private final RpHttp http;

    ShareService(RpHttp http) {
        this.http = http;
    }

    ShareResult share(ShareRequest r) {
        if (r == null) throw new IllegalArgumentException("eid: share: ShareRequest шаардлагатай");
        String boundary = boundary();
        byte[] body = body(r, boundary);
        String path = Routes.SHARE.expand();
        RpHttp.Result res;
        try {
            res = http.exchange("POST", path, body, "multipart/form-data; boundary=" + boundary, TIMEOUT);
        } catch (EidException.Api e) {
            throw new EidException.Share(e);
        }
        Json.Obj o = res.obj("POST /share");
        return new ShareResult(Dto.integer(o, "sent"), o.optString("sha256"), Dto.integer(o, "signatures"), o.optString("docID"), Dto.raw(res));
    }

    /** Go mime/multipart {@code randomBoundary}: 30 random bytes, hex. */
    private static String boundary() {
        byte[] b = new byte[30];
        RANDOM.nextBytes(b);
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }

    /**
     * The multipart/form-data body exactly as Go {@code shareBody} writes it (mime/multipart): to × n, subject, message,
     * lang, filename (empty values skipped), then the file part. The file part's filename is ASCII only (the
     * Content-Disposition); a Unicode name travels in the filename field (the CA prefers it).
     */
    static byte[] body(ShareRequest r, String boundary) {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        boolean[] first = {true};
        for (String a : r.to()) field(b, boundary, first, "to", a == null ? "" : a);
        String[][] kv = {{"subject", r.subject()}, {"message", r.message()}, {"lang", r.lang()}, {"filename", r.filename()}};
        for (String[] p : kv) if (p[1] != null && !p[1].isEmpty()) field(b, boundary, first, p[0], p[1]);
        String partName = "document.pdf";
        if (r.filename() != null && !r.filename().isEmpty() && printableAscii(r.filename())) partName = r.filename();
        part(b, boundary, first, "Content-Disposition: form-data; name=\"file\"; filename=\"" + quoteEscape(partName) + "\"\r\n"
            + "Content-Type: application/pdf\r\n");
        b.writeBytes(r.file());
        b.writeBytes(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII));
        return b.toByteArray();
    }

    private static void field(ByteArrayOutputStream b, String boundary, boolean[] first, String k, String v) {
        part(b, boundary, first, "Content-Disposition: form-data; name=\"" + quoteEscape(k) + "\"\r\n");
        b.writeBytes(v.getBytes(StandardCharsets.UTF_8));
    }

    private static void part(ByteArrayOutputStream b, String boundary, boolean[] first, String headers) {
        String sep = first[0] ? "--" + boundary + "\r\n" : "\r\n--" + boundary + "\r\n";
        first[0] = false;
        b.writeBytes((sep + headers + "\r\n").getBytes(StandardCharsets.UTF_8));
    }

    /** Go {@code quoteEscaper}: \ → \\, " → \". */
    static String quoteEscape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    static boolean printableAscii(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) return false;
        }
        return true;
    }

    ShareInfo info() {
        Json.Obj d = http.getJson(Routes.DISCOVERY_PATH, null).obj("GET " + Routes.DISCOVERY_PATH);
        Json.Obj s = d.optObj("share");
        if (s == null) {
            return new ShareInfo(false, "", List.of(), List.of(), 0, 0, 0, 0, 0, "", new ShareInfo.Quota(0, 0, 0), false, "");
        }
        List<ShareInfo.Format> formats = new ArrayList<>();
        for (Json.Obj f : Dto.objects(s, "formats")) formats.add(new ShareInfo.Format(f.optString("name"), f.optString("extension"), f.optString("mime")));
        Json.Obj q = Dto.obj(s, "quota");
        return new ShareInfo(s.optBool("enabled", false), s.optString("endpoint"), Collections.unmodifiableList(formats), Dto.strings(s, "languages"),
            Dto.integer(s, "maxFileBytes"), Dto.integer(s, "maxFilenameChars"), Dto.integer(s, "maxMessageChars"), Dto.integer(s, "maxRecipients"),
            Dto.integer(s, "maxSubjectChars"), s.optString("permission"),
            new ShareInfo.Quota(Dto.integer(q, "perRPHour"), Dto.integer(q, "perRPDay"), Dto.integer(q, "perRecipientDay")),
            s.optBool("requiresValidSignature", false), Dto.text(s));
    }
}
