package mn.eidmongolia.eid.pades;

/**
 * The visible stamp's final rect ({@link SignatureAppearance} coordinates, pt) and how it was chosen — Go
 * {@code pades.Placement}. Surface {@link PlacementStatus#OVERLAP} / {@link PlacementStatus#UNSCANNED} to the signer — the
 * signature is valid either way.
 *
 * @param page 1-based page the stamp is on (input PDF page numbering)
 */
public record Placement(int page, double x, double y, double width, double height, PlacementStatus status) {
}
