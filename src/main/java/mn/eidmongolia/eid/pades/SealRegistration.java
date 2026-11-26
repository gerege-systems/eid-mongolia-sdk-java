package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Body of CA {@code POST /seal/{orgEtsi}/registrations} (CA V158 {@code dto.SealRegisterRequest}; Go
 * {@code eid.SealRegistration}, TS {@code SealRegisterInput}) — the organisation-seal counterpart of {@link Registration}.
 * {@link #toJson()} gives exactly the CA's field names (the CA rejects unknown fields: no medium, sessionID, onBehalfOf,
 * signerEtsi or pageSha256). Built by {@link Completed#sealRegistration()} after {@link EidPades#sealPdf}; sent with
 * {@code EidClient.seal().registerSealedPdf(orgEtsi, registration)}. The hashes have the same meaning as in
 * {@link Registration}.
 *
 * @param docID               lowercase UUID
 * @param revIndex            the seal's position in the file (1…16)
 * @param cms                 CMS DER, standard base64 (1…28 672 bytes decoded)
 * @param fileName            optional — the name shown on /verify (≤ 120 characters); null / blank = none
 * @param priorRevisionSha256 prior CA-assembled (mode A) signatures by revision hash — null by default (see
 *                            {@link #priorSignatures()})
 * @param priorSignatures     SDK-only (not in {@link #toJson()}): every prior signature's CMS and revision hash, document
 *                            order — on 409 {@code PRIOR_MISMATCH} {@code registerSealedPdf} retries the revision splits
 */
public record SealRegistration(String docID, int revIndex, String cms, String fileName, String inSha256, String sigRevSha256,
                               String outSha256, List<String> priorCmsSha256, List<String> priorRevisionSha256,
                               List<Registration.PriorSignature> priorSignatures) {

    /** The body's members in the CA's order (TS {@code SEAL_REGISTER_FIELDS}; CA {@code dto.SealRegisterRequest}). */
    public static final List<String> FIELDS = List.of("docID", "revIndex", "cms", "fileName", "inSha256", "sigRevSha256", "outSha256",
        "priorCmsSha256", "priorRevisionSha256");
    /** The CA's limit on the CMS (CA {@code padesRegisterMaxCMS} = the PAdES placeholder). */
    public static final int MAX_CMS_BYTES = 28_672;
    /** The CA's limit on {@link #fileName()} in characters (code points). */
    public static final int MAX_FILE_NAME = 120;

    private static final Pattern UUID_LOWER = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final Pattern HEX64 = Pattern.compile("^[0-9a-f]{64}$");

    public SealRegistration {
        priorCmsSha256 = priorCmsSha256 == null ? null : List.copyOf(priorCmsSha256);
        priorRevisionSha256 = priorRevisionSha256 == null ? null : List.copyOf(priorRevisionSha256);
        priorSignatures = priorSignatures == null ? List.of() : List.copyOf(priorSignatures);
    }

    /**
     * The CA's {@code normalizeSealRegister} shape rules without the network (Go {@code SealRegistration.Validate}, TS
     * {@code buildSealRegisterBody}): docID a lowercase UUID, revIndex 1–16, fileName ≤ 120 characters (when given), cms
     * standard base64 of 1…28 672 bytes, inSha256 / sigRevSha256 / outSha256 and every prior* hash 64 lowercase hex, and
     * |priorCmsSha256| + |priorRevisionSha256| = revIndex − 1.
     *
     * @throws IllegalArgumentException the first rule broken
     */
    public void validate() {
        if (docID == null || !UUID_LOWER.matcher(docID).matches()) throw bad("docID нь жижиг үсгийн UUID");
        if (revIndex < 1 || revIndex > 16) throw bad("revIndex 1–16");
        String fn = fileName == null ? "" : fileName.strip();
        if (fn.codePointCount(0, fn.length()) > MAX_FILE_NAME) throw bad("fileName ≤ " + MAX_FILE_NAME + " тэмдэгт");
        byte[] raw;
        try {
            raw = cms == null ? new byte[0] : Base64.getDecoder().decode(cms);
        } catch (IllegalArgumentException e) {
            throw bad("cms стандарт base64 биш");
        }
        if (raw.length == 0 || !Base64.getEncoder().encodeToString(raw).equals(cms)) throw bad("cms стандарт base64 биш (эсвэл хоосон)");
        if (raw.length > MAX_CMS_BYTES) throw bad("cms 1…" + MAX_CMS_BYTES + " байт");
        int prior = (priorCmsSha256 == null ? 0 : priorCmsSha256.size()) + (priorRevisionSha256 == null ? 0 : priorRevisionSha256.size());
        if (prior != revIndex - 1) throw bad("priorCmsSha256 + priorRevisionSha256 нийт revIndex − 1");
        hex("inSha256", inSha256);
        hex("sigRevSha256", sigRevSha256);
        hex("outSha256", outSha256);
        if (priorCmsSha256 != null) for (String h : priorCmsSha256) hex("priorCmsSha256", h);
        if (priorRevisionSha256 != null) for (String h : priorRevisionSha256) hex("priorRevisionSha256", h);
    }

    private static IllegalArgumentException bad(String m) {
        return new IllegalArgumentException("eid: seal register: " + m);
    }

    private static void hex(String name, String v) {
        if (v == null || !HEX64.matcher(v).matches()) throw bad(name + " 64 жижиг hex биш");
    }

    /**
     * A copy whose prior signatures are sent by CMS hash where {@code asRevision[i]} is false and by revision hash where it
     * is true (the 409 {@code PRIOR_MISMATCH} retry; {@link #priorSignatures()} must cover every prior signature).
     *
     * @throws IllegalArgumentException asRevision's length ≠ the number of prior signatures
     */
    public SealRegistration withPriorByRevision(boolean[] asRevision) {
        if (asRevision == null || asRevision.length != priorSignatures.size()) throw new IllegalArgumentException("asRevision");
        List<String> cmsList = new ArrayList<>();
        List<String> rev = new ArrayList<>();
        for (int i = 0; i < priorSignatures.size(); i++) {
            if (asRevision[i]) rev.add(priorSignatures.get(i).revisionSha256());
            else cmsList.add(priorSignatures.get(i).cmsSha256());
        }
        return new SealRegistration(docID, revIndex, cms, fileName, inSha256, sigRevSha256, outSha256, cmsList.isEmpty() ? null : cmsList,
            rev.isEmpty() ? null : rev, priorSignatures);
    }

    /**
     * The JSON body in the CA's field order (TS {@code SEAL_REGISTER_FIELDS}): docID, revIndex, cms, fileName (trimmed,
     * omitted when blank), inSha256, sigRevSha256, outSha256, priorCmsSha256 / priorRevisionSha256 (omitted when empty).
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        str(sb, "docID", docID);
        key(sb, "revIndex");
        sb.append(revIndex);
        str(sb, "cms", cms);
        String fn = fileName == null ? "" : fileName.strip();
        if (!fn.isEmpty()) str(sb, "fileName", fn);
        str(sb, "inSha256", inSha256);
        str(sb, "sigRevSha256", sigRevSha256);
        str(sb, "outSha256", outSha256);
        list(sb, "priorCmsSha256", priorCmsSha256);
        list(sb, "priorRevisionSha256", priorRevisionSha256);
        return sb.append('}').toString();
    }

    private static void key(StringBuilder sb, String k) {
        if (sb.length() > 1) sb.append(',');
        sb.append('"').append(k).append("\":");
    }

    private static void str(StringBuilder sb, String k, String v) {
        if (v == null) return;
        key(sb, k);
        Json.quote(sb, v);
    }

    private static void list(StringBuilder sb, String k, List<String> v) {
        if (v == null || v.isEmpty()) return;
        key(sb, k);
        sb.append('[');
        for (int i = 0; i < v.size(); i++) {
            if (i > 0) sb.append(',');
            Json.quote(sb, v.get(i));
        }
        sb.append(']');
    }
}
