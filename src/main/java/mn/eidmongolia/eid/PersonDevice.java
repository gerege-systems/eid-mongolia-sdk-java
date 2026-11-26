package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * One of the citizen's devices (Go {@code PersonDevice}).
 *
 * @param platform APNS | FCM
 * @param deactivatedAt null while active
 */
public record PersonDevice(String deviceId, String documentNumber, String platform, String pushTopic, Instant enrolledAt,
    boolean active, Instant deactivatedAt) {

    static PersonDevice of(Json.Obj o, String op) {
        return new PersonDevice(o.optString("deviceId"), o.optString("documentNumber"), o.optString("platform"),
            o.optString("pushTopic"), Dto.instant(o, "enrolledAt", op), o.optBool("active", false), Dto.instant(o, "deactivatedAt", op));
    }
}
