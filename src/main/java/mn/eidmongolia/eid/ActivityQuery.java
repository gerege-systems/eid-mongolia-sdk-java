package mn.eidmongolia.eid;

/**
 * {@link PersonService#activity} filter (Go {@code ActivityQuery}). Zero values = the server's defaults (limit 20,
 * offset 0, every flow).
 *
 * @param flow "AUTHENTICATION" | "SIGNATURE" | "" / null (all)
 * @param limit 1–200 (the server caps it); 0 = default
 * @param offset 0 = from the start
 */
public record ActivityQuery(String flow, int limit, int offset) {
}
