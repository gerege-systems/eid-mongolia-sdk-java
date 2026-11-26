package mn.eidmongolia.eid;

import java.util.List;

/** GET /certificates/etsi/{personEtsi} (Go {@code PersonCertificates}); {@code rawJson} = the server's raw JSON. */
public record PersonCertificates(String personEtsi, CertCounts counts, List<PersonCertificate> certificates, String rawJson) {
}
