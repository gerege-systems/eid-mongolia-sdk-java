package mn.eidmongolia.eid.pades;

import java.util.List;
import mn.eidmongolia.eid.pades.validate.PadesSupport;

/** The writer pieces the PDF validator re-uses ({@link PadesSupport}): the structure pre-check and the stamp generator. */
final class ValidateSupport implements PadesSupport {
    static final ValidateSupport INSTANCE = new ValidateSupport();

    private ValidateSupport() {
    }

    @Override
    public boolean structureOk(byte[] doc) {
        try {
            Structure.check(doc);
            return true;
        } catch (Structure.Failure e) {
            return false;
        }
    }

    @Override
    public List<byte[]> appearanceObjects(int w, int h, int rotate, String name, String role, String lang, String date, String url,
        boolean seal, int[] ids) {
        // The seal stamp variants (APPEARANCE_SPEC.md §6, golden v12/v13) are not in this writer yet: a visible e-Seal stamp
        // is never recognised as the writer's own (fail closed — the earlier signature reads modified_after_signing).
        if (seal) throw new UnsupportedOperationException("seal stamp");
        return Appearance.objects(new Appearance.Params(w, h, rotate, name, role, lang, date, url), ids);
    }

    @Override
    public byte[] visibleWidget(String fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId) {
        return Appearance.widget(fieldName, rect, new PdfRef(pageId, pageGen), sigId, formId);
    }
}
