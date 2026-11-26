package mn.eidmongolia.eid;

import java.util.List;

/** GET /person/children/etsi/{personEtsi} (Go {@code PersonChildren}). */
public record PersonChildren(List<PersonChild> children, String rawJson) {
}
