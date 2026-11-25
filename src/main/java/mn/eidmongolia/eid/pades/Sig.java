package mn.eidmongolia.eid.pades;

import java.security.PublicKey;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

/** Signature verification by algorithm OID (CMS / OCSP / CRL / TSA tokens). */
final class Sig {
    private Sig() {
    }

    private static final Map<String, String> NAMES = new HashMap<>();
    private static final Map<String, String> DIGESTS = new HashMap<>();

    static {
        NAMES.put("1.2.840.113549.1.1.5", "SHA1withRSA");
        NAMES.put("1.2.840.113549.1.1.11", "SHA256withRSA");
        NAMES.put("1.2.840.113549.1.1.12", "SHA384withRSA");
        NAMES.put("1.2.840.113549.1.1.13", "SHA512withRSA");
        NAMES.put("1.2.840.10045.4.1", "SHA1withECDSA");
        NAMES.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
        NAMES.put("1.2.840.10045.4.3.3", "SHA384withECDSA");
        NAMES.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
        DIGESTS.put("1.3.14.3.2.26", "SHA-1");
        DIGESTS.put("2.16.840.1.101.3.4.2.1", "SHA-256");
        DIGESTS.put("2.16.840.1.101.3.4.2.2", "SHA-384");
        DIGESTS.put("2.16.840.1.101.3.4.2.3", "SHA-512");
    }

    static String digestName(String oid) {
        return DIGESTS.get(oid);
    }

    /** CMS SignerInfo: digestAlgorithm + signatureAlgorithm (rsaEncryption / ecPublicKey or a combined OID). */
    static String cmsAlgorithm(String digestOid, String sigOid) {
        String n = NAMES.get(sigOid);
        if (n != null) return n;
        String d = DIGESTS.get(digestOid);
        if (d == null) return null;
        d = d.replace("-", "");
        switch (sigOid) {
            case "1.2.840.113549.1.1.1":
                return d + "withRSA";
            case "1.2.840.10045.2.1":
                return d + "withECDSA";
            default:
                return null;
        }
    }

    static boolean verify(String alg, PublicKey key, byte[] data, byte[] sig) {
        if (alg == null) return false;
        try {
            Signature s = Signature.getInstance(alg);
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    static boolean verifyOid(String sigOid, PublicKey key, byte[] data, byte[] sig) {
        return verify(NAMES.get(sigOid), key, data, sig);
    }
}
