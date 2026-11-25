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

    private static EidPadesException internal(Exception e) {
        EidPadesException x = new EidPadesException.Internal(e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName());
        x.initCause(e);
        return x;
    }
}
