package mn.eidmongolia.eid;

import java.util.List;

/** GET /devices/etsi/{personEtsi} (Go {@code PersonDevices}). */
public record PersonDevices(String personEtsi, List<PersonDevice> devices, int activeCount, int total, String rawJson) {
}
