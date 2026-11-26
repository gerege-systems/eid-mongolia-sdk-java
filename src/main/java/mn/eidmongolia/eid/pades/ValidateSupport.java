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
        return Appearance.objects(new Appearance.Params(w, h, rotate, name, role, lang, date, url, seal), ids);
    }

    @Override
    public byte[] visibleWidget(String fieldName, long[] rect, int pageId, int pageGen, int sigId, int formId) {
        return Appearance.widget(fieldName, rect, new PdfRef(pageId, pageGen), sigId, formId);
    }
}
