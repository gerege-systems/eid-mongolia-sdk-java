package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * A child in the citizen's guardianship (Go {@code PersonChild}).
 *
 * @param name «Овог Нэр»
 * @param birthDate YYYY-MM-DD
 * @param registered the child has eID on a phone
 * @param certNotAfter the certificate's end (age 18); null when not registered
 */
public record PersonChild(String etsi, String regNo, String name, String birthDate, boolean registered, Instant certNotAfter) {

    static PersonChild of(Json.Obj o, String op) {
        return new PersonChild(o.optString("etsi"), o.optString("regNo"), o.optString("name"), o.optString("birthDate"),
            o.optBool("registered", false), Dto.instant(o, "certNotAfter", op));
    }
}
