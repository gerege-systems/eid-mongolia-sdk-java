package mn.eidmongolia.eid.pades;

import java.util.List;

/**
 * {@link EidPades#suggestPlacement} result — Go {@code pades.Suggestion} (PLACEMENT_SPEC.md §6b), pt. page, x, y, width,
 * height, status are what {@link EidPades#prepare} returns in {@link Prepared#placement()} for the same PDF and
 * appearance. A UI rendering the page at {@code s} px/pt with a top-left origin maps {@code left = x·s},
 * {@code top = (pageHeight − y − height)·s}; back: {@code x = left/s}, {@code y = pageHeight − top/s − height}, then
 * prepare with {@code exact = true}.
 *
 * @param page       1-based, resolved (appearance page 0 → PLACEMENT_SPEC §1a)
 * @param pageWidth  visible size of {@code page} (CropBox, else MediaBox, after /Rotate)
 * @param pageCount  pages in /Pages tree order
 * @param pages      visible size of every page; index 0 = page 1; (0, 0) = geometry unreadable
 */
public record PlacementSuggestion(int page, double x, double y, double width, double height, PlacementStatus status,
                                  double pageWidth, double pageHeight, int pageCount, List<PageSize> pages) {
    public PlacementSuggestion {
        pages = List.copyOf(pages);
    }

    /** A page's visible size in pt. */
    public record PageSize(double width, double height) {
    }
}
