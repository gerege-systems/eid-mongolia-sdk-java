package mn.eidmongolia.eid.pades;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Opaque prepare → complete state. Same layout as the Go reference (`pades/state.go`): "EIDPADES1" ‖ uint32 BE header
 * length ‖ JSON header (Go field order) ‖ prepared PDF. Adds `priorCmsSha256` (Go ignores unknown keys when decoding).
 */
final class PrepState {
    private static final byte[] MAGIC = Text.latin1("EIDPADES1");

    final String docId;
    final byte[] signerCert;
    final List<byte[]> chain;
    final byte[] signedAttrs;
    final long[] byteRange;
    final int revIndex;
    final String inSha256;
    final boolean hasPage;
    final String pageSha256;
    final String claimedRole;
    final List<String> priorCmsSha256;
    final byte[] pdf;
    /** Cleaned document name for the CA registration (Go `prepState.FileName`). */
    final String fileName;

    PrepState(String docId, byte[] signerCert, List<byte[]> chain, byte[] signedAttrs, long[] byteRange, int revIndex, String inSha256,
              boolean hasPage, String pageSha256, String claimedRole, List<String> priorCmsSha256, byte[] pdf, String fileName) {
        this.docId = docId;
        this.signerCert = signerCert;
        this.chain = chain;
        this.signedAttrs = signedAttrs;
        this.byteRange = byteRange;
        this.revIndex = revIndex;
        this.inSha256 = inSha256;
        this.hasPage = hasPage;
        this.pageSha256 = pageSha256;
        this.claimedRole = claimedRole;
        this.priorCmsSha256 = priorCmsSha256;
        this.pdf = pdf;
        this.fileName = fileName;
    }

    byte[] encode() {
        StringBuilder h = new StringBuilder("{\"docId\":");
        Json.quote(h, docId);
        h.append(",\"signerCert\":");
        Json.quote(h, Text.base64(signerCert));
        h.append(",\"chain\":[");
        for (int i = 0; i < chain.size(); i++) {
            if (i > 0) h.append(',');
            Json.quote(h, Text.base64(chain.get(i)));
        }
        h.append("],\"signedAttrs\":");
        Json.quote(h, Text.base64(signedAttrs));
        h.append(",\"byteRange\":[").append(byteRange[0]).append(',').append(byteRange[1]).append(',').append(byteRange[2]).append(',')
            .append(byteRange[3]).append(']');
        h.append(",\"revIndex\":").append(revIndex);
        h.append(",\"inSha256\":");
        Json.quote(h, inSha256);
        h.append(",\"hasPage\":").append(hasPage);
        if (pageSha256 != null && !pageSha256.isEmpty()) {
            h.append(",\"pageSha256\":");
            Json.quote(h, pageSha256);
        }
        if (claimedRole != null && !claimedRole.isEmpty()) {
            h.append(",\"claimedRole\":");
            Json.quote(h, claimedRole);
        }
        if (fileName != null && !fileName.isEmpty()) {
            h.append(",\"fileName\":");
            Json.quote(h, fileName);
        }
        h.append(",\"preparedSha256\":");
        Json.quote(h, Text.hex(Cms.sha256(pdf)));
        h.append(",\"priorCmsSha256\":[");
        for (int i = 0; i < priorCmsSha256.size(); i++) {
            if (i > 0) h.append(',');
            Json.quote(h, priorCmsSha256.get(i));
        }
        h.append("]}");
        byte[] head = h.toString().getBytes(StandardCharsets.UTF_8);
        int n = head.length;
        byte[] out = new byte[MAGIC.length + 4 + n + pdf.length];
        System.arraycopy(MAGIC, 0, out, 0, MAGIC.length);
        out[MAGIC.length] = (byte) (n >>> 24);
        out[MAGIC.length + 1] = (byte) (n >> 16);
        out[MAGIC.length + 2] = (byte) (n >> 8);
        out[MAGIC.length + 3] = (byte) n;
        System.arraycopy(head, 0, out, MAGIC.length + 4, n);
        System.arraycopy(pdf, 0, out, MAGIC.length + 4 + n, pdf.length);
        return out;
    }

    private static void require(boolean ok, String msg) {
        if (!ok) throw new IllegalArgumentException(msg);
    }

    static PrepState decode(byte[] b) {
        require(b.length >= MAGIC.length + 4 && Arrays.equals(Arrays.copyOf(b, MAGIC.length), MAGIC), "state header");
        int p = MAGIC.length;
        long n = ((b[p] & 0xffL) << 24) | ((b[p + 1] & 0xffL) << 16) | ((b[p + 2] & 0xffL) << 8) | (b[p + 3] & 0xffL);
        p += 4;
        require(n <= b.length - p, "state truncated");
        Object parsed = Json.parse(Arrays.copyOfRange(b, p, p + (int) n));
        require(parsed instanceof Json.Obj, "state header is not an object");
        Json.Obj h = (Json.Obj) parsed;
        byte[] pdf = Arrays.copyOfRange(b, p + (int) n, b.length);
        require(Text.hex(Cms.sha256(pdf)).equals(h.getString("preparedSha256")), "prepared PDF hash mismatch");
        List<Object> br = h.getArr("byteRange");
        require(br.size() == 4, "byteRange");
        long[] byteRange = new long[4];
        for (int i = 0; i < 4; i++) {
            require(br.get(i) instanceof Json.Num, "byteRange");
            byteRange[i] = ((Json.Num) br.get(i)).longValue();
        }
        List<byte[]> chain = new ArrayList<>();
        List<Object> ca = h.optArr("chain");
        if (ca != null) for (Object o : ca) chain.add(Text.unbase64((String) o));
        List<String> prior = new ArrayList<>();
        List<Object> pa = h.optArr("priorCmsSha256");
        if (pa != null) for (Object o : pa) prior.add((String) o);
        PrepState s = new PrepState(
            h.getString("docId"), Text.unbase64(h.getString("signerCert")), chain, Text.unbase64(h.getString("signedAttrs")), byteRange,
            h.getInt("revIndex"), h.getString("inSha256"), h.optBool("hasPage", false), h.optNonEmpty("pageSha256"),
            h.optNonEmpty("claimedRole"), prior, pdf, h.optNonEmpty("fileName"));
        require(s.signedAttrs.length > 0 && s.signerCert.length > 0 && s.pdf.length > 0 && s.revIndex >= 1, "state incomplete");
        return s;
    }
}
