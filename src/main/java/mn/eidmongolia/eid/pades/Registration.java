package mn.eidmongolia.eid.pades;

import java.util.List;

/**
 * Body of CA {@code POST /pdf/signatures} (Go {@code eid.PDFSignatureRegistration}) — {@link #toJson()} gives the exact
 * field names (the CA rejects unknown fields).
 *
 * @param cms                 CMS DER, standard base64
 * @param pageSha256          only for revIndex 1
 * @param priorRevisionSha256 prior CA-assembled (mode A) signatures by revision hash — null by default; on 409
 *                            {@code PRIOR_MISMATCH} move the matching {@link #priorSignatures()} from priorCmsSha256 to here
 * @param priorSignatures     SDK-only (not in {@link #toJson()}): every prior signature's CMS and revision hash, document order
 */
public record Registration(String docID, int revIndex, Medium medium, String sessionID, String cms, String fileName,
                           String inSha256, String pageSha256, String sigRevSha256, String outSha256, List<String> priorCmsSha256,
                           List<String> priorRevisionSha256, String onBehalfOf, String signerEtsi,
                           List<PriorSignature> priorSignatures) {

    public Registration {
        priorCmsSha256 = priorCmsSha256 == null ? null : List.copyOf(priorCmsSha256);
        priorRevisionSha256 = priorRevisionSha256 == null ? null : List.copyOf(priorRevisionSha256);
        priorSignatures = priorSignatures == null ? List.of() : List.copyOf(priorSignatures);
    }

    /**
     * One prior signature's two keys (Go {@code eid.PDFPriorSignature}): the CA knows a client-side row by its CMS hash and
     * a CA-assembled (mode A) row by its revision hash.
     */
    public record PriorSignature(String cmsSha256, String revisionSha256) {
    }

    /** A copy whose leading prior signatures are sent by revision hash (409 PRIOR_MISMATCH retry, CA mode A). */
    public Registration withPriorByRevision(int k) {
        if (k < 0 || k > priorSignatures.size()) throw new IllegalArgumentException("k");
        List<String> rev = new java.util.ArrayList<>();
        List<String> cmsList = new java.util.ArrayList<>();
        for (int i = 0; i < priorSignatures.size(); i++) {
            if (i < k) rev.add(priorSignatures.get(i).revisionSha256());
            else cmsList.add(priorSignatures.get(i).cmsSha256());
        }
        return new Registration(docID, revIndex, medium, sessionID, cms, fileName, inSha256, pageSha256, sigRevSha256, outSha256,
            cmsList.isEmpty() ? null : cmsList, rev.isEmpty() ? null : rev, onBehalfOf, signerEtsi, priorSignatures);
    }

    /** JSON object; null / absent optional fields are omitted (Go {@code omitempty}). */
    public String toJson() {
        StringBuilder sb = new StringBuilder("{");
        str(sb, "docID", docID);
        key(sb, "revIndex");
        sb.append(revIndex);
        str(sb, "medium", medium.wire());
        str(sb, "sessionID", sessionID);
        str(sb, "cms", cms);
        str(sb, "fileName", fileName);
        str(sb, "inSha256", inSha256);
        str(sb, "pageSha256", pageSha256);
        str(sb, "sigRevSha256", sigRevSha256);
        str(sb, "outSha256", outSha256);
        list(sb, "priorCmsSha256", priorCmsSha256);
        list(sb, "priorRevisionSha256", priorRevisionSha256);
        str(sb, "onBehalfOf", onBehalfOf);
        str(sb, "signerEtsi", signerEtsi);
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
