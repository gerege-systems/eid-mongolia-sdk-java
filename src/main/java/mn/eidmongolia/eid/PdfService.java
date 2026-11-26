package mn.eidmongolia.eid;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import mn.eidmongolia.eid.pades.Medium;
import mn.eidmongolia.eid.pades.Registration;

/**
 * PDF signature registration ({@link EidClient#pdf()}, Go {@code PDFService} pdfregister.go, TS
 * {@code SignApi.registerSignature}).
 */
public final class PdfService {
    /** The CA's revIndex bound (1…16, the same as the 16-signature PAdES limit). */
    static final int MAX_REV_INDEX = 16;
    private final RpHttp http;
    private final Duration timeout;

    PdfService(RpHttp http, Duration timeout) {
        this.http = http;
        this.timeout = timeout;
    }

    /**
     * POST /pdf/signatures (SIGN permission): enters a client-side PAdES signature into the CA registry (docID,
     * /verify). Required after {@code EidPades.complete}; the body is
     * {@link mn.eidmongolia.eid.pades.Completed#registration}. A repeat with the same body is idempotent (200,
     * {@link PdfSignatureRegistered#created()} false).
     *
     * <p>Which prior signature is a CA-assembled (mode A) row cannot be told from the file: on 409 PRIOR_MISMATCH, when
     * {@link Registration#priorSignatures()} covers every prior signature and no priorRevisionSha256 was given, the
     * combinations are tried (first k by revision, then — up to 4 priors — every other split), as Go / TS do.
     *
     * @throws IllegalArgumentException a missing docID / revIndex (or one outside 1…16) / cms / medium, phone without sessionID, revIndex 1
     *     without pageSha256 (no request is sent)
     * @throws EidException.Api code ∈ {@link EidErrorCodes#PDF_REGISTER} (also {@link EidException.Forbidden})
     */
    public PdfSignatureRegistered registerSignature(Registration r) {
        if (r == null || r.docID() == null || r.docID().isEmpty() || r.revIndex() < 1 || r.revIndex() > MAX_REV_INDEX || r.cms() == null || r.cms().isEmpty()) {
            throw new IllegalArgumentException("eid: pdf register: docID, revIndex (1…" + MAX_REV_INDEX + "), cms заавал");
        }
        if (r.medium() == null) throw new IllegalArgumentException("eid: pdf register: medium нь phone | token");
        if (r.medium() == Medium.PHONE && (r.sessionID() == null || r.sessionID().isEmpty())) {
            throw new IllegalArgumentException("eid: pdf register: утсанд sessionID заавал");
        }
        if (r.revIndex() == 1 && (r.pageSha256() == null || r.pageSha256().isEmpty())) {
            throw new IllegalArgumentException("eid: pdf register: revIndex 1-д pageSha256 заавал (баталгаажуулалтын хуудастай)");
        }
        List<Registration.PriorSignature> prior = r.priorSignatures();
        boolean manual = r.priorRevisionSha256() != null && !r.priorRevisionSha256().isEmpty();
        try {
            return register(r);
        } catch (EidException.Api first) {
            if (!isPriorMismatch(first) || manual || prior.isEmpty() || prior.size() != r.revIndex() - 1) throw first;
            for (boolean[] asRevision : priorSplits(prior.size())) {
                List<String> cms = new ArrayList<>();
                List<String> rev = new ArrayList<>();
                for (int i = 0; i < prior.size(); i++) {
                    if (asRevision[i]) rev.add(prior.get(i).revisionSha256());
                    else cms.add(prior.get(i).cmsSha256());
                }
                Registration next = new Registration(r.docID(), r.revIndex(), r.medium(), r.sessionID(), r.cms(), r.fileName(),
                    r.inSha256(), r.pageSha256(), r.sigRevSha256(), r.outSha256(), cms.isEmpty() ? null : cms,
                    rev.isEmpty() ? null : rev, r.onBehalfOf(), r.signerEtsi(), prior);
                try {
                    return register(next);
                } catch (EidException.Api e) {
                    if (!isPriorMismatch(e)) throw e;
                }
            }
            throw first;
        }
    }

    private PdfSignatureRegistered register(Registration r) {
        String path = Routes.PDF_SIGNATURES.expand();
        RpHttp.Result res = http.exchange("POST", path, EidCrypto.utf8(r.toJson()), "application/json", timeout);
        Json.Obj o = res.obj("POST " + path);
        long rev = o.optLong("revIndex", 0);
        return new PdfSignatureRegistered(o.optString("docID"), (int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, rev)),
            o.optString("registeredAt"), o.optString("verifyUrl"), res.status() == 201);
    }

    private static boolean isPriorMismatch(EidException.Api e) {
        return EidErrorCodes.PRIOR_MISMATCH.equals(e.code());
    }

    /**
     * The attempts after PRIOR_MISMATCH (true = that prior signature by revision): first the leading k (k = 1…n; mode A
     * precedes client-side ones), then, for n ≤ 4, every remaining combination. All-by-CMS (k = 0) was already tried.
     * Same order as Go / TS {@code priorSplits}.
     */
    static List<boolean[]> priorSplits(int n) {
        List<boolean[]> out = new ArrayList<>();
        Set<Integer> seen = new HashSet<>();
        for (int k = 1; k <= n; k++) {
            int m = (1 << k) - 1;
            seen.add(m);
            out.add(mask(m, n));
        }
        if (n <= 4) {
            for (int m = 1; m < 1 << n; m++) if (!seen.contains(m)) out.add(mask(m, n));
        }
        return out;
    }

    private static boolean[] mask(int m, int n) {
        boolean[] b = new boolean[n];
        for (int i = 0; i < n; i++) b[i] = (m & (1 << i)) != 0;
        return b;
    }
}
