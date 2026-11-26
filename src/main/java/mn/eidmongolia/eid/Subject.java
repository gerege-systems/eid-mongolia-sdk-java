package mn.eidmongolia.eid;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import mn.eidmongolia.eid.internal.Cert;

/**
 * The citizen certificate's subject fields (Go {@code Subject}, TS {@code CertSubject}; RFC 5280 / ETSI EN 319 412-2).
 * Absent fields are "".
 *
 * @param givenName GIVENNAME (2.5.4.42), Latin (ICAO, upper case)
 * @param surname SURNAME (2.5.4.4), Latin
 * @param commonName CN
 * @param serialNumber SERIALNUMBER (2.5.4.5): the ETSI identifier, e.g. PNOMN-&lt;civil id&gt; / NTRMN-&lt;registry&gt;
 * @param country C (e.g. MN)
 */
public record Subject(String givenName, String surname, String commonName, String serialNumber, String country) {
    private static final Subject EMPTY = new Subject("", "", "", "", "");

    /**
     * Parses a certificate's subject (Go {@code ParseSubject}): CN and SERIALNUMBER as Go {@code pkix.Name} (the last
     * occurrence), the first C, GIVENNAME and SURNAME. Parsing only — whether to trust the certificate is the
     * validator's decision: use the subject of a {@link VerifiedIdentity} / {@link VerifiedSignature}.
     */
    public static Subject parse(X509Certificate cert) {
        if (cert == null) return EMPTY;
        Cert c;
        try {
            c = Cert.parse(cert.getEncoded());
        } catch (CertificateEncodingException | RuntimeException e) {
            return EMPTY;
        }
        return of(c);
    }

    static Subject of(Cert c) {
        return new Subject(s(c.subjectAttrFirst("2.5.4.42")), s(c.subjectAttrFirst("2.5.4.4")), s(c.subjectAttr("2.5.4.3")),
            s(c.subjectAttr("2.5.4.5")), s(c.subjectAttrFirst("2.5.4.6")));
    }

    private static String s(String v) {
        return v == null ? "" : v;
    }
}
