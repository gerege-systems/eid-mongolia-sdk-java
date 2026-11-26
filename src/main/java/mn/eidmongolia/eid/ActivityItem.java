package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * One activity record (Go {@code ActivityItem}; kinds/reasons: CA EID_PERSON_PKI §Activity — new codes may appear, show
 * unknown ones generically).
 *
 * @param kind AUTH | SIGN | PIN_CHECK | ENROLL | TOKEN_AUTH | …
 * @param flow AUTHENTICATION | SIGNATURE (AUTH / SIGN only)
 * @param outcome OK | DENIED | FAILED
 */
public record ActivityItem(String id, String sessionId, String kind, String flow, String outcome, String reason,
    String pinSlot, String endResult, String rpName, String subsystemName, String docText, String interactionType,
    String documentNumber, String clientIp, Instant timestamp, String onBehalfOfName) {

    static ActivityItem of(Json.Obj o, String op) {
        return new ActivityItem(o.optString("id"), o.optString("sessionId"), o.optString("kind"), o.optString("flow"),
            o.optString("outcome"), o.optString("reason"), o.optString("pinSlot"), o.optString("endResult"), o.optString("rpName"),
            o.optString("subsystemName"), o.optString("docText"), o.optString("interactionType"), o.optString("documentNumber"),
            o.optString("clientIp"), Dto.instant(o, "timestamp", op), o.optString("onBehalfOfName"));
    }
}
