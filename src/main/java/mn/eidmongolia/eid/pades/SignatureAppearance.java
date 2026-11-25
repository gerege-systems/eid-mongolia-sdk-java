package mn.eidmongolia.eid.pades;

/**
 * Visible signature placement — Go reference {@code pades.Appearance} (APPEARANCE_SPEC.md §1). Coordinates in pt from the
 * bottom-left corner of the page's CropBox (else MediaBox) AFTER /Rotate (as displayed); x to the right, y up. Each value
 * is rounded to 0.01 pt; height ≥ 45 pt (QR), else REQUEST_INVALID.
 *
 * @param page   input document page, 1-based; 0 → the input's last page that is not an eID verify page (PLACEMENT_SPEC §1a)
 * @param lang   "mn" | "en"; null → {@link PrepareOptions#lang()} (else mn)
 * @param exact  draw the stamp exactly at page/x/y/width/height (a position the signer chose on a page preview): never
 *               moved off page content; {@link Placement#status()} is then REQUESTED, or OVERLAP when content is under
 *               the rect (UNSCANNED when the page cannot be scanned). false = x/y is only the preferred spot.
 */
public record SignatureAppearance(int page, double x, double y, double width, double height, String lang, boolean exact) {
    /** Page 0 (the last content page), language from the options, not exact. */
    public SignatureAppearance(double x, double y, double width, double height) {
        this(0, x, y, width, height, null, false);
    }

    public SignatureAppearance withPage(int p) {
        return new SignatureAppearance(p, x, y, width, height, lang, exact);
    }

    public SignatureAppearance withLang(String l) {
        return new SignatureAppearance(page, x, y, width, height, l, exact);
    }

    public SignatureAppearance withExact(boolean e) {
        return new SignatureAppearance(page, x, y, width, height, lang, e);
    }
}
