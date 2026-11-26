package mn.eidmongolia.eid.pades.validate;

import java.util.List;

/**
 * INTERNAL — not part of the SDK's API. The pieces of the PAdES writer ({@code mn.eidmongolia.eid.pades}, package-private
 * there) the validator re-uses: the structure pre-check (Go {@code CheckStructure}) and the stamp generator, whose output
 * the own-signer appearance check (APPEARANCE_SPEC.md §5) compares object by object. Supplied by
 * {@code EidPades.validatePdf}; public only because Java has no cross-package internal visibility.
 */
public interface PadesSupport {
    /** Go CheckStructure (nesting / object-stream graph limits); false = the document is rejected as PDF_INVALID. */
    boolean structureOk(byte[] doc);

    /**
     * Go core appearanceObjects / TS {@code appearanceObjects}: the /AP /N form XObject and its two fonts (11 bodies,
     * ids = [form, F1 ×5, F2 ×5]). w/h in h100. Throws a RuntimeException for parameters the writer rejects or does not
     * support (the caller treats that as "not the writer's stamp").
     */
    List<byte[]> appearanceObjects(int w, int h, int rotate, String name, String role, String lang, String date, String url,
        boolean seal, int[] ids);

    /** TS {@code visibleWidget}: the visible signature field/widget body; rect in h100 user space. */
    byte[] visibleWidget(String fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId);
}
