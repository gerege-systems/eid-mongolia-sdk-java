package mn.eidmongolia.eid;

import java.util.List;

/** GET /rp/activity/etsi/{personEtsi} — RP-scoped (Go {@code PersonActivity}). */
public record PersonActivity(String personEtsi, ActivityCounts counts, List<ActivityItem> sessions, int total, int limit,
    int offset, String rawJson) {
}
