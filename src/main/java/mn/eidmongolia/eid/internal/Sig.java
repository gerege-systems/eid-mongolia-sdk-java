package mn.eidmongolia.eid.internal;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Signature verification by algorithm OID (CMS / OCSP / CRL / TSA tokens). */
public final class Sig {
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

    public static String digestName(String oid) {
        return DIGESTS.get(oid);
    }

    /** CMS SignerInfo: digestAlgorithm + signatureAlgorithm (rsaEncryption / ecPublicKey or a combined OID). */
    public static String cmsAlgorithm(String digestOid, String sigOid) {
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

    /**
     * Every signature check of the SDK goes through here. An ECDSA algorithm ({@code *withECDSA}) additionally requires an
     * EC key and a DER (r, s) with 0 &lt; r, s &lt; n ({@link #ecdsaDerInRange}) BEFORE the JDK sees it.
     */
    public static boolean verify(String alg, PublicKey key, byte[] data, byte[] sig) {
        if (alg == null || key == null || sig == null) return false;
        if (alg.endsWith("withECDSA") && !(key instanceof ECPublicKey && ecdsaDerInRange((ECPublicKey) key, sig))) return false;
        try {
            Signature s = Signature.getInstance(alg);
            s.initVerify(key);
            s.update(data);
            return s.verify(sig);
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean verifyOid(String sigOid, PublicKey key, byte[] data, byte[] sig) {
        return verify(NAMES.get(sigOid), key, data, sig);
    }

    /**
     * 0 &lt; r &lt; n and 0 &lt; s &lt; n for the key's curve order n (FIPS 186-4 §6.4.2 step 1; Go {@code ecdsa.Verify}).
     * Defence in depth against JDK verifier bugs of the CVE-2022-21449 class (r = s = 0 accepted).
     */
    public static boolean ecdsaInRange(ECPublicKey key, BigInteger r, BigInteger s) {
        if (key == null || r == null || s == null) return false;
        BigInteger n = key.getParams().getOrder();
        return r.signum() > 0 && s.signum() > 0 && r.compareTo(n) < 0 && s.compareTo(n) < 0;
    }

    /**
     * A DER ECDSA-Sig-Value (SEQUENCE of exactly two INTEGERs, nothing after it) whose r and s are in range
     * ({@link #ecdsaInRange}). Anything else → false.
     */
    public static boolean ecdsaDerInRange(ECPublicKey key, byte[] der) {
        try {
            Der.Tlv seq = Der.parse(der);
            if (seq.tag != Der.SEQUENCE || seq.start != 0 || seq.end != der.length) return false;
            List<Der.Tlv> rs = seq.children();
            if (rs.size() != 2 || rs.get(0).tag != Der.INTEGER || rs.get(1).tag != Der.INTEGER) return false;
            if (rs.get(0).length() == 0 || rs.get(1).length() == 0) return false;
            return ecdsaInRange(key, rs.get(0).bigInt(), rs.get(1).bigInt());
        } catch (RuntimeException e) {
            return false;
        }
    }
}
