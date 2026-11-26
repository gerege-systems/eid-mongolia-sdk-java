package mn.eidmongolia.eid;

/**
 * rsassa-pss response parameters (signature.signatureAlgorithmParameters; Go {@code SignatureAlgorithmParameters}).
 *
 * @param maskGenAlgorithm the MGF algorithm (e.g. id-mgf1), "" when absent
 * @param maskGenHashAlgorithm the MGF1 hash, "" when absent
 * @param saltLength null = absent in the response
 * @param trailerField "" when absent
 */
public record SignatureAlgorithmParameters(String hashAlgorithm, String maskGenAlgorithm, String maskGenHashAlgorithm,
    Integer saltLength, String trailerField) {
}
