/**
 * INTERNAL — not part of the SDK's API; may change in any release without notice. DER reader/writer, X.509 certificate
 * fields, signature-by-OID, ASN.1 time and OCSP helpers shared by {@code mn.eidmongolia.eid} (validator, OCSP revocation
 * checker) and {@code mn.eidmongolia.eid.pades} (CMS, TSA, LTV, «My QR»). The classes are public only because Java
 * has no cross-package internal visibility.
 */
package mn.eidmongolia.eid.internal;
