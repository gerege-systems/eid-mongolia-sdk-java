package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.Test;

/** POST /share (multipart) and shareInfo (ports of Go share_test.go; TS share.test.ts). */
public class ShareTest {
    static final byte[] PDF = "%PDF-1.7\n…".getBytes(StandardCharsets.UTF_8);
    static final Pattern BOUNDARY = Pattern.compile("^multipart/form-data; boundary=([0-9a-f]{60})$");

    /** [name, filename, content-type, value] per part, parsed from the request (a strict reader of Go's layout). */
    static List<String[]> parts(EidHttpRequest r) {
        Matcher m = BOUNDARY.matcher(r.headers().get("Content-Type"));
        assertTrue(r.headers().get("Content-Type"), m.matches());
        String b = m.group(1);
        String body = new String(r.body(), StandardCharsets.UTF_8);
        assertTrue(body.startsWith("--" + b + "\r\n"));
        assertTrue(body.endsWith("\r\n--" + b + "--\r\n"));
        String inner = body.substring(("--" + b + "\r\n").length(), body.length() - ("\r\n--" + b + "--\r\n").length());
        List<String[]> out = new ArrayList<>();
        for (String p : inner.split("\r\n--" + b + "\r\n", -1)) {
            int sep = p.indexOf("\r\n\r\n");
            String head = p.substring(0, sep);
            String value = p.substring(sep + 4);
            String name = "";
            String fn = "";
            String ct = "";
            for (String h : head.split("\r\n")) {
                Matcher d = Pattern.compile("^Content-Disposition: form-data; name=\"([^\"]*)\"(?:; filename=\"([^\"]*)\")?$").matcher(h);
                if (d.matches()) {
                    name = d.group(1);
                    fn = d.group(2) == null ? "" : d.group(2);
                } else if (h.startsWith("Content-Type: ")) {
                    ct = h.substring("Content-Type: ".length());
                } else {
                    fail("unexpected header " + h);
                }
            }
            out.add(new String[] {name, fn, ct, value});
        }
        return out;
    }

    // Go TestShareRequestAndResult
    @Test
    public void requestAndResult() {
        FakeRp rp = FakeRp.reply(200, "{\"sent\":2,\"sha256\":\"ab\",\"signatures\":1,\"docID\":\"d-1\"}");
        ShareResult res = rp.client().share(new ShareRequest(PDF, "гэрээ.pdf", List.of("a@x.mn", "b@x.mn"), "Гэрээ", "Зурна уу", "en"));
        FakeRp.assertRequest(rp.last(), "POST", "/share");
        assertEquals("Bearer " + FakeRp.CREDS.apiSecret(), rp.last().headers().get("Authorization"));
        assertEquals(Duration.ofSeconds(150), rp.last().timeout());
        assertEquals(2, res.sent());
        assertEquals("ab", res.sha256());
        assertEquals(1, res.signatures());
        assertEquals("d-1", res.docId());
        assertFalse(res.rawJson().isEmpty());
        List<String[]> p = parts(rp.last());
        String[][] want = {{"to", "", "", "a@x.mn"}, {"to", "", "", "b@x.mn"}, {"subject", "", "", "Гэрээ"}, {"message", "", "", "Зурна уу"},
            {"lang", "", "", "en"}, {"filename", "", "", "гэрээ.pdf"}, {"file", "document.pdf", "application/pdf", new String(PDF, StandardCharsets.UTF_8)}};
        assertEquals(want.length, p.size());
        for (int i = 0; i < want.length; i++) {
            assertEquals(String.join("|", want[i]), String.join("|", p.get(i)));
            assertTrue(ShareService.FORM_FIELDS.contains(p.get(i)[0]));
        }
        // An ASCII filename is the file part's name too; quotes and backslashes escaped (Go quoteEscaper).
        rp.client().share(new ShareRequest(PDF, "a\"b\\c.pdf", List.of("a@x.mn"), null, null, null));
        assertTrue(rp.lastBody(), rp.lastBody().contains("name=\"file\"; filename=\"a\\\"b\\\\c.pdf\"\r\n"));
    }

    /** The bytes Go mime/multipart writes for the same boundary (fixed here) — layout, CRLFs, header order. */
    @Test
    public void goMultipartBytes() {
        byte[] got = ShareService.body(new ShareRequest("PDF".getBytes(StandardCharsets.US_ASCII), "a.pdf", List.of("x@y.mn"), "S", "", "mn"), "B");
        String want = "--B\r\nContent-Disposition: form-data; name=\"to\"\r\n\r\nx@y.mn"
            + "\r\n--B\r\nContent-Disposition: form-data; name=\"subject\"\r\n\r\nS"
            + "\r\n--B\r\nContent-Disposition: form-data; name=\"lang\"\r\n\r\nmn"
            + "\r\n--B\r\nContent-Disposition: form-data; name=\"filename\"\r\n\r\na.pdf"
            + "\r\n--B\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.pdf\"\r\nContent-Type: application/pdf\r\n\r\nPDF"
            + "\r\n--B--\r\n";
        assertEquals(want, new String(got, StandardCharsets.UTF_8));
    }

    // Go TestShareOptionalFieldsOmitted
    @Test
    public void optionalFieldsOmitted() {
        FakeRp rp = FakeRp.reply(200, "{\"sent\":1,\"sha256\":\"cd\",\"signatures\":2}");
        ShareResult res = rp.client().share(new ShareRequest(PDF, null, List.of("a@x.mn"), null, null, null));
        List<String[]> p = parts(rp.last());
        assertEquals(2, p.size());
        assertEquals("to", p.get(0)[0]);
        assertEquals("file", p.get(1)[0]);
        assertEquals("document.pdf", p.get(1)[1]);
        assertEquals("", res.docId());
    }

    // Go TestShareErrors + TestShareAuthErrors
    @Test
    public void errors() {
        Object[][] cases = {
            {422, "{\"error\":\"…\",\"code\":\"FILE_NOT_SIGNED\",\"reason\":\"untrusted\"}", null},
            {502, "{\"error\":\"…\",\"code\":\"MAIL_FAILED\",\"sent\":1,\"failed\":1,\"recipients\":[\"sent\",\"failed\"]}", null},
            {429, "{\"error\":\"…\",\"code\":\"RATE_LIMITED\"}", "30"},
            {503, "{\"error\":\"…\",\"code\":\"VALIDATOR_BUSY\"}", "30"},
            {503, "{\"error\":\"…\",\"code\":\"SHARE_DISABLED\"}", null},
            {400, "{\"error\":\"…\",\"code\":\"REQUEST_INVALID\"}", null},
            {413, "<html>nginx</html>", null},
        };
        for (Object[] c : cases) {
            int status = (Integer) c[0];
            FakeRp rp = new FakeRp(q -> new EidHttpResponse(status, c[2] == null ? Map.of() : Map.of("Retry-After", List.of((String) c[2])),
                ((String) c[1]).getBytes(StandardCharsets.UTF_8)));
            try {
                rp.client().share(new ShareRequest(PDF, null, List.of("a@x.mn"), null, null, null));
                fail("" + status);
            } catch (EidException.Share e) {
                assertEquals(status, e.status());
                assertTrue(e.getMessage(), e.getMessage().startsWith("eid: share "));
                switch (status) {
                    case 422:
                        assertEquals(EidErrorCodes.FILE_NOT_SIGNED, e.code());
                        assertEquals(ShareRequest.REASON_UNTRUSTED, e.reason());
                        break;
                    case 502:
                        assertEquals(EidErrorCodes.MAIL_FAILED, e.code());
                        assertEquals(1, e.sent());
                        assertEquals(1, e.failed());
                        assertEquals(List.of(ShareRequest.RECIPIENT_SENT, ShareRequest.RECIPIENT_FAILED), e.recipients());
                        assertFalse(e.retryable());
                        break;
                    case 429:
                        assertEquals(Duration.ofSeconds(30), e.retryAfter());
                        assertTrue(e.retryable());
                        break;
                    case 503:
                        assertEquals(c[2] != null, e.retryable());
                        break;
                    case 400:
                        assertEquals(EidErrorCodes.REQUEST_INVALID, e.code());
                        break;
                    default:
                        assertEquals("", e.code());
                }
            }
        }
        for (int status : new int[] {401, 403}) {
            try {
                FakeRp.reply(status, "{\"error\":\"…\"}").client().share(new ShareRequest(PDF, null, List.of("a@x.mn"), null, null, null));
                fail();
            } catch (EidException.Share e) {
                fail("401/403 are not ShareErrors");
            } catch (EidException.Authentication | EidException.Forbidden expected) {
                assertEquals(status, expected.status());
            }
        }
        assertEquals(List.of("REQUEST_INVALID", "FILE_EMPTY", "RECIPIENT_REQUIRED", "TOO_MANY_RECIPIENTS", "RECIPIENT_INVALID",
            "RECIPIENT_DUPLICATE", "FILE_TOO_LARGE", "FILE_TYPE_NOT_SUPPORTED", "FILE_NOT_SIGNED", "RATE_LIMITED", "MAIL_FAILED",
            "SHARE_DISABLED", "MAIL_UNAVAILABLE", "VALIDATOR_UNAVAILABLE", "VALIDATOR_BUSY"), EidErrorCodes.SHARE);
    }

    // Go TestShareInfo
    @Test
    public void info() {
        FakeRp rp = FakeRp.reply(200, "{\"share\":{\"enabled\":false,\"endpoint\":\"https://rp.eidmongolia.mn/share\","
            + "\"formats\":[{\"extension\":\".pdf\",\"mime\":\"application/pdf\",\"name\":\"pdf\"}],\"languages\":[\"mn\",\"en\"],"
            + "\"maxFileBytes\":3080192,\"maxFilenameChars\":120,\"maxMessageChars\":1000,\"maxRecipients\":5,\"maxSubjectChars\":150,"
            + "\"permission\":\"SIGN\",\"quota\":{\"perRPDay\":200,\"perRPHour\":30,\"perRecipientDay\":10},\"requiresValidSignature\":true}}");
        ShareInfo s = rp.client().shareInfo();
        FakeRp.assertRequest(rp.last(), "GET", "/.well-known/eid");
        assertFalse(s.enabled());
        assertEquals(3080192, s.maxFileBytes());
        assertEquals(5, s.maxRecipients());
        assertEquals(new ShareInfo.Quota(30, 200, 10), s.quota());
        assertEquals(".pdf", s.formats().get(0).extension());
        assertEquals(List.of("mn", "en"), s.languages());
        assertTrue(s.requiresValidSignature());
        assertFalse(s.rawJson().isEmpty());
        assertFalse(FakeRp.reply(200, "{}").client().shareInfo().enabled());
    }
}
