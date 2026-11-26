package mn.eidmongolia.eid;

import java.security.cert.X509Certificate;

/**
 * Checks whether a citizen certificate is revoked (Go {@code RevocationChecker}, TS {@code RevocationChecker}) — OCSP
 * ({@link OcspRevocationChecker}) or the RP's own CRL / OCSP code. Implementations verify the answer's signature,
 * issuer, serial and freshness themselves and never report a network failure as {@link RevocationStatus#GOOD}.
 */
@FunctionalInterface
public interface RevocationChecker {
    /**
     * @param cert the certificate to check
     * @param issuer its direct issuer from the validator's trust pool; null when none was found
     * @return GOOD, REVOKED or UNKNOWN (null counts as UNKNOWN)
     * @throws EidException.Ocsp no answer (= UNKNOWN with a cause; the validator's mode decides). Any other runtime
     *     exception is a checker failure: the validator does not trust the certificate and rethrows it.
     */
    RevocationStatus check(X509Certificate cert, X509Certificate issuer);
}
