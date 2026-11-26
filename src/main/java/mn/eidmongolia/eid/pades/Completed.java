package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.List;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;

/**
 * {@link EidPades#complete} output. {@link #registration} builds the CA {@code POST /pdf/signatures} body the RP backend
 * posts as is (Go {@code pades.Registration}). Hashes are lowercase hex.
 *
 * <ul>
 *   <li>{@link #pdf()} — signed PAdES-BASELINE-LT document; {@link #cms()} — the embedded CMS SignedData (DER)</li>
 *   <li>{@link #pageSha256()} — document after the verify page, before the signature revision ({@link #hasPage()} only)</li>
 *   <li>{@link #sigRevSha256()} — the signature revision (before DSS) — doc[:ByteRange end]</li>
 *   <li>{@link #priorCmsSha256()} / {@link #priorRevisionSha256()} — earlier signatures, document order (informational —
 *       do not send both lists for the same signatures, use {@link #registration})</li>
 *   <li>{@link #fileName()} — the cleaned {@link PrepareOptions#fileName()}; null when not given or invalid</li>
 *   <li>{@link #claimedRole()} — carried through the state; non-null → {@link #registration} requires onBehalfOf</li>
 * </ul>
 */
public final class Completed {
    private final byte[] pdf;
    private final byte[] cms;
    private final String docId;
    private final String outSha256;
    private final String inSha256;
    private final boolean hasPage;
    private final String pageSha256;
    private final byte[] signerCert;
    private final int revIndex;
    private final String sigRevSha256;
    private final List<String> priorCmsSha256;
    private final List<String> priorRevisionSha256;
    private final String fileName;
    private final String claimedRole;
    private final Placement placement;

    Completed(byte[] pdf, byte[] cms, String docId, String outSha256, String inSha256, boolean hasPage, String pageSha256,
              byte[] signerCert, int revIndex, String sigRevSha256, List<String> priorCmsSha256, List<String> priorRevisionSha256,
              String fileName, String claimedRole) {
        this(pdf, cms, docId, outSha256, inSha256, hasPage, pageSha256, signerCert, revIndex, sigRevSha256, priorCmsSha256,
            priorRevisionSha256, fileName, claimedRole, null);
    }

    private Completed(byte[] pdf, byte[] cms, String docId, String outSha256, String inSha256, boolean hasPage, String pageSha256,
                      byte[] signerCert, int revIndex, String sigRevSha256, List<String> priorCmsSha256, List<String> priorRevisionSha256,
                      String fileName, String claimedRole, Placement placement) {
        this.placement = placement;
        this.pdf = pdf;
        this.cms = cms;
        this.docId = docId;
        this.outSha256 = outSha256;
        this.inSha256 = inSha256;
        this.hasPage = hasPage;
        this.pageSha256 = pageSha256;
        this.signerCert = signerCert;
        this.revIndex = revIndex;
        this.sigRevSha256 = sigRevSha256;
        this.priorCmsSha256 = List.copyOf(priorCmsSha256);
        this.priorRevisionSha256 = List.copyOf(priorRevisionSha256);
        this.fileName = fileName;
        this.claimedRole = claimedRole;
    }

    public byte[] pdf() {
        return pdf.clone();
    }

    public byte[] cms() {
        return cms.clone();
    }

    byte[] pdfRaw() {
        return pdf;
    }

    byte[] cmsRaw() {
        return cms;
    }

    public String docId() {
        return docId;
    }

    public String outSha256() {
        return outSha256;
    }

    public String inSha256() {
        return inSha256;
    }

    public boolean hasPage() {
        return hasPage;
    }

    public String pageSha256() {
        return pageSha256;
    }

    public byte[] signerCert() {
        return signerCert.clone();
    }

    public int revIndex() {
        return revIndex;
    }

    public String sigRevSha256() {
        return sigRevSha256;
    }

    public List<String> priorCmsSha256() {
        return priorCmsSha256;
    }

    public List<String> priorRevisionSha256() {
        return priorRevisionSha256;
    }

    public String fileName() {
        return fileName;
    }

    public String claimedRole() {
        return claimedRole;
    }

    /**
     * Where the visible organisation seal stamp was drawn — filled by {@link EidPades#sealPdf} only (null when the seal
     * is invisible). In the citizen flow it is {@link Prepared#placement()}; {@link EidPades#complete} leaves it null.
     */
    public Placement placement() {
        return placement;
    }

    /** This result with [p] as {@link #placement()} (Go SealPDF: res.Placement = p.Placement). */
    Completed withPlacement(Placement p) {
        return new Completed(pdf, cms, docId, outSha256, inSha256, hasPage, pageSha256, signerCert, revIndex, sigRevSha256, priorCmsSha256,
            priorRevisionSha256, fileName, claimedRole, p);
    }

    /**
     * The CA organisation-seal registration body ({@code POST /seal/{orgEtsi}/registrations}; Go {@code pades.SealRegistration}
     * / {@code Completed.SealRegistration}, TS {@code done.sealRegistration}) for an {@link EidPades#sealPdf} result — send it
     * with {@code EidClient.seal().registerSealedPdf(orgEtsi, …)} within 7 days (required after {@link SealOptions#qr()}).
     * The hashes are those of {@link #registration}: inSha256 = the input, sigRevSha256 = the output up to the end of the
     * ByteRange, outSha256 = the output, priorCmsSha256 = every earlier signature's /Contents CMS (document order);
     * {@link SealRegistration#priorSignatures()} keeps the revision hashes for the PRIOR_MISMATCH retry. fileName =
     * {@link SealOptions#fileName()} (cleaned), or none.
     *
     * @throws EidPadesException.RequestInvalid no docId (a signed document without a verify page / QR seal stamp — pass
     *     {@link SealOptions#docId()}), or the signer is not an e-Seal certificate (a citizen signature uses
     *     {@link #registration})
     */
    public SealRegistration sealRegistration() {
        if (docId == null || docId.isEmpty()) {
            throw new EidPadesException.RequestInvalid("docId empty — pass SealOptions.docId for a signed document without one");
        }
        if (!mn.eidmongolia.eid.SealService.isSealCertificate(signerCert)) {
            throw new EidPadesException.RequestInvalid("the signer is not an e-Seal certificate — a citizen signature uses registration()");
        }
        List<Registration.PriorSignature> prior = new ArrayList<>();
        if (!priorCmsSha256.isEmpty() && priorRevisionSha256.size() == priorCmsSha256.size()) {
            for (int i = 0; i < priorCmsSha256.size(); i++) {
                prior.add(new Registration.PriorSignature(priorCmsSha256.get(i), priorRevisionSha256.get(i)));
            }
        }
        return new SealRegistration(docId, revIndex, Text.base64(cms), fileName, inSha256, sigRevSha256, outSha256,
            priorCmsSha256.isEmpty() ? null : priorCmsSha256, null, prior);
    }

    /** {@link #registration(Medium, String, String)} with the medium inferred from sessionId. */
    public Registration registration(String sessionId, String onBehalfOf) {
        return registration(null, sessionId, onBehalfOf);
    }

    /**
     * The CA registration body for this signature (Go {@code pades.Registration}). Prior signatures go as
     * {@code priorCmsSha256} only; {@link Registration#priorSignatures()} keeps both keys for the 409 {@code PRIOR_MISMATCH}
     * retry ({@link Registration#withPriorByRevision}).
     *
     * @param medium     null = inferred the way the CA pairs them: sessionId given → PHONE, else TOKEN
     * @param sessionId  the RAW_DIGEST_SIGNATURE session (required for PHONE, absent for TOKEN)
     * @param onBehalfOf NTRMN-… (required when prepare had a claimedRole)
     * @throws EidPadesException.RequestInvalid revIndex 1 without a verification page, no valid fileName in prepare, PHONE
     *                                          without sessionId, TOKEN with sessionId, or claimedRole without onBehalfOf
     */
    public Registration registration(Medium medium, String sessionId, String onBehalfOf) {
        if (revIndex == 1 && !hasPage) {
            throw new EidPadesException.RequestInvalid(
                "the CA registers a first signature only with the verification page (PrepareOptions.verifyPage)");
        }
        if (fileName == null || fileName.isEmpty()) throw new EidPadesException.RequestInvalid("fileName empty (PrepareOptions.fileName)");
        String session = sessionId == null || sessionId.isEmpty() ? null : sessionId;
        Medium m = medium != null ? medium : session != null ? Medium.PHONE : Medium.TOKEN;
        if (m == Medium.PHONE && session == null) {
            throw new EidPadesException.RequestInvalid("medium phone requires sessionId (the RAW_DIGEST_SIGNATURE session)");
        }
        if (m == Medium.TOKEN && session != null) throw new EidPadesException.RequestInvalid("medium token takes no sessionId");
        String obo = onBehalfOf == null || onBehalfOf.isEmpty() ? null : onBehalfOf;
        if (claimedRole != null && !claimedRole.isEmpty() && obo == null) {
            throw new EidPadesException.RequestInvalid("claimedRole was prepared: onBehalfOf (NTRMN-…) is required");
        }
        String etsi;
        try {
            etsi = Cert.parse(signerCert).subjectAttr(Cert.OID_SERIAL_NUMBER);
        } catch (Exception e) {
            etsi = null;
        }
        List<Registration.PriorSignature> prior = new ArrayList<>();
        if (priorRevisionSha256.size() == priorCmsSha256.size()) {
            for (int i = 0; i < priorCmsSha256.size(); i++) {
                prior.add(new Registration.PriorSignature(priorCmsSha256.get(i), priorRevisionSha256.get(i)));
            }
        }
        return new Registration(docId, revIndex, m, session, Text.base64(cms), fileName, inSha256, revIndex == 1 ? pageSha256 : null,
            sigRevSha256, outSha256, priorCmsSha256.isEmpty() ? null : priorCmsSha256, null, obo, etsi, prior);
    }
}
