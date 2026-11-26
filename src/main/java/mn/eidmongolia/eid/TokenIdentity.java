package mn.eidmongolia.eid;

/** The citizen the CA verified (Go {@code TokenIdentity}); givenName / surname from the KYC registry (Cyrillic). */
public record TokenIdentity(String etsi, String givenName, String surname) {
}
