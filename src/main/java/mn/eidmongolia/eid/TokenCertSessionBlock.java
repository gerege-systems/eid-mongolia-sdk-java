package mn.eidmongolia.eid;

/**
 * GET /session/{id} {@code tokenCertificate} (USB token certificate issuance; Go {@code TokenCertSessionBlock}).
 *
 * @param status PENDING | ISSUED | FAILED | EXPIRED
 * @param errorCode the FAILED reason; "" otherwise
 */
public record TokenCertSessionBlock(String status, String errorCode, String authSerialHex, String signSerialHex) {
}
