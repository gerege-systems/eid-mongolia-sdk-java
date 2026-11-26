package mn.eidmongolia.eid.pades;

import java.util.Objects;

/**
 * eID Mongolia client-side PAdES — the PDF never reaches an eID server. Plain-Java port of the signing path,
 * byte-identical to the Go reference ({@code eid-mongolia-sdk-go/pades}, profile {@code pades-client/1}) on the shared
 * golden vectors; Android/iOS/.NET {@code EidPades} 1:1.
 *
 * <p>Flow: {@link #prepare} → have {@link Prepared#dtbs()} signed via an RP-API signature session
 * ({@code RAW_DIGEST_SIGNATURE}) on the phone or a USB token → {@link #complete} (RFC 3161 TSA + OCSP/CRL over the network,
 * DSS) → register {@link Completed#registration} through the raw RP-API ({@code POST /pdf/signatures}). No validator
 * here — verification is a CA registry lookup / the Go backend SDK.
 *
 * <p>Thread-safe, no global mutable state. {@link #prepare} and {@link #suggestPlacement} are CPU work; {@link #complete}
 * blocks on the network (TSA, OCSP, CRL) — run it on a worker thread.
 */
public final class EidPades {
    /** PDF/CMS profile implemented by this SDK (Go {@code pades.ProfileVersion}). */
    public static final String VERSION = Pades.PROFILE;

    private EidPades() {
    }

    /**
     * Prepares the signature revision (optional verification page and visible stamp) and returns the 32-byte DTBS.
     * No network.
     *
     * @throws EidPadesException with a stable {@link EidPadesException#code()}
     */
    public static Prepared prepare(byte[] pdf, PrepareOptions options) {
        Objects.requireNonNull(pdf, "pdf");
        Objects.requireNonNull(options, "options");
        try {
            return Pades.prepare(pdf, options);
        } catch (EidPadesException e) {
            throw e;
        } catch (Exception e) {
            throw internal(e);
        }
    }

    /**
     * Runs {@link #prepare}'s placement on {@code pdf} without signing — no certificate, no network — so a UI can show the
     * default stamp position, the page sizes, and whether a chosen rect lies over content (Go {@code pades.SuggestPlacement},
     * PLACEMENT_SPEC.md §6b).
     *
     * <p>Errors, in order: PDF_TOO_LARGE, PDF_INVALID, REQUEST_INVALID (appearance values), PDF_ENCRYPTED, REQUEST_INVALID
     * (page > page count, page geometry, rect outside the page). Not checked here ({@link #prepare} does): prior
     * signatures, the signer certificate, whether the signer's name fits the stamp.
     */
    public static PlacementSuggestion suggestPlacement(byte[] pdf, SignatureAppearance appearance) {
        Objects.requireNonNull(pdf, "pdf");
        Objects.requireNonNull(appearance, "appearance");
        try {
            return Pades.suggestPlacement(pdf, appearance);
        } catch (EidPadesException e) {
            throw e;
        } catch (Exception e) {
            throw internal(e);
        }
    }

    /** {@link #complete(byte[], byte[], CompleteOptions)} with {@link CompleteOptions#DEFAULT}. */
    public static Completed complete(byte[] state, byte[] signature) {
        return complete(state, signature, CompleteOptions.DEFAULT);
    }

    /**
     * Verifies the citizen's signature over the DTBS, timestamps it (RFC 3161), embeds the CMS and appends the DSS
     * revision (OCSP/CRL) → PAdES-BASELINE-LT. Blocking network I/O.
     *
     * @param state     {@link Prepared#state()}
     * @param signature RSA PKCS#1 v1.5, ECDSA r‖s or DER — selected by the certificate's key
     * @throws EidPadesException with a stable {@link EidPadesException#code()}; {@link EidPadesException#retryable()} for
     *                           TSA/LTV outages
     */
    public static Completed complete(byte[] state, byte[] signature, CompleteOptions options) {
        Objects.requireNonNull(state, "state");
        Objects.requireNonNull(signature, "signature");
        try {
            return Pades.complete(state, signature, options == null ? CompleteOptions.DEFAULT : options, Pades.Env.system());
        } catch (EidPadesException e) {
            throw e;
        } catch (Exception e) {
            throw internal(e);
        }
    }

    /**
     * Seals a PDF with the organisation's e-Seal (Go {@code pades.SealPDF}): the seal certificate
     * ({@code GET /seal/certificate/{orgEtsi}}) → {@link #prepare} → the DTBS sealed via {@code POST /seal/{orgEtsi}}
     * (SHA-256) → {@link #complete} (TSA + OCSP/CRL + DSS + self-validation) → PAdES-BASELINE-LT. The PDF never reaches
     * the CA — only the 32-byte DTBS. Validators (CA, SDKs) classify the signature as usage "seal".
     *
     * <p>Invisible only in this release ({@link SealOptions}): {@code options.invisible()} false → REQUEST_INVALID
     * before any network call.
     *
     * @throws EidPadesException SIGNER_INVALID — the certificate is not an e-Seal one, or the organisation's seal
     *     certificate changed between the two calls; the {@link #prepare} / {@link #complete} codes
     * @throws mn.eidmongolia.eid.EidException the {@link Sealer}'s errors unchanged (403 — no SEAL right; 429 — retryable;
     *     409 seal codes; 503 SEAL_SERVICE_DISABLED — never retried, no unsealed file is returned)
     */
    public static Completed sealPdf(Sealer sealer, String orgEtsi, byte[] pdf, SealOptions options) {
        return sealPdf(sealer, orgEtsi, pdf, options, Pades.Env.system());
    }

    static Completed sealPdf(Sealer sealer, String orgEtsi, byte[] pdf, SealOptions options, Pades.Env env) {
        Objects.requireNonNull(pdf, "pdf");
        if (sealer == null) throw new EidPadesException.RequestInvalid("Sealer null");
        SealOptions o = options == null ? SealOptions.builder().build() : options;
        if (!o.invisible()) {
            throw new EidPadesException.RequestInvalid("the visible seal stamp is not supported yet (golden v12/v13) — set SealOptions.invisible(true)");
        }
        mn.eidmongolia.eid.SealCertificate sc = sealer.certificate(orgEtsi);
        byte[] der = sc == null ? new byte[0] : sc.certificate();
        mn.eidmongolia.eid.internal.Cert cert;
        try {
            cert = mn.eidmongolia.eid.internal.Cert.parse(der);
        } catch (IllegalArgumentException e) {
            throw new EidPadesException.SignerInvalid("seal certificate does not parse");
        }
        if (!mn.eidmongolia.eid.SealService.isSealCertificate(cert.raw)) {
            throw new EidPadesException.SignerInvalid("not an e-Seal certificate (KeyUsage must be nonRepudiation only)");
        }
        PrepareOptions.Builder pb = PrepareOptions.builder(cert.raw).chain(o.chain()).signerName(o.signerName()).reason(o.reason())
            .signingTime(o.signingTime());
        Prepared p = prepare(pdf, pb.build());
        mn.eidmongolia.eid.SealResult r = sealer.seal(orgEtsi, p.dtbs(), mn.eidmongolia.eid.HashAlgorithm.SHA_256);
        if (r == null || !java.util.Arrays.equals(r.certificate(), cert.raw)) {
            throw new EidPadesException.SignerInvalid("the organisation's seal certificate changed while sealing — try again");
        }
        try {
            return Pades.complete(p.state(), r.signature(), o.complete(), env);
        } catch (EidPadesException e) {
            throw e;
        } catch (Exception e) {
            throw internal(e);
        }
    }

    /**
     * Validates every PAdES/CMS signature of a signed or sealed PDF locally (Go {@code pades.ValidatePDF}, TS
     * {@code validatePdf}; the same rules and JSON report as the CA's {@code /v3/validate/pdf}): ByteRange / messageDigest
     * integrity, the CMS signature, the chain to the national root, key usage, validity, RFC 3161 timestamp, revisions
     * after the signature (modified_after_signing; visible stamps per APPEARANCE_SPEC §5), revocation (DSS, and online
     * OCSP/CRL unless {@code offline}), LTV and the certificate level. Blocking network I/O unless offline.
     *
     * @throws mn.eidmongolia.eid.pades.validate.ValidatePdfException PDF_TOO_LARGE, PDF_INVALID, PDF_ENCRYPTED,
     *     PDF_NO_SIGNATURE, PDF_TOO_MANY_SIGNATURES, REQUEST_INVALID
     */
    public static mn.eidmongolia.eid.pades.validate.PdfReport validatePdf(byte[] pdf, mn.eidmongolia.eid.pades.validate.ValidatePdfOptions options) {
        Objects.requireNonNull(pdf, "pdf");
        return mn.eidmongolia.eid.pades.validate.Engine.run(pdf,
            options == null ? mn.eidmongolia.eid.pades.validate.ValidatePdfOptions.DEFAULT : options, ValidateSupport.INSTANCE, DefaultHttp.INSTANCE);
    }

    private static EidPadesException internal(Exception e) {
        EidPadesException x = new EidPadesException.Internal(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        x.initCause(e);
        return x;
    }
}
