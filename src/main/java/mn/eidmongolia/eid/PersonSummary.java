package mn.eidmongolia.eid;

/**
 * GET /person/summary/etsi/{personEtsi} — the dashboard's counts in one call (Go {@code PersonSummary}). Names as in
 * {@link Person} (lastName = patronymic, familyName = clan name).
 *
 * @param nationality ISO 3166-1 alpha-3 / ICAO 9303; "" when unknown (not the certificate's country)
 */
public record PersonSummary(String personEtsi, String firstName, String lastName, String familyName, String nationality,
    CertCounts certificates, ActivityCounts activity, int devicesActive, int devicesTotal, int representationCount,
    String rawJson) {
}
