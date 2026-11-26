package mn.eidmongolia.eid;

import java.util.List;

/**
 * GET /organization/representations/etsi/{personEtsi} (Go {@code RepresentationsResponse}).
 *
 * @param personEtsi the server's value, else the requested ETSI
 * @param representations never null (empty when none)
 * @param rawJson the server's raw JSON (fields the SDK does not parse)
 */
public record RepresentationsResponse(String personEtsi, List<Representation> representations, String rawJson) {
}
