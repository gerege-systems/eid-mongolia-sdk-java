package mn.eidmongolia.eid;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Sig;
import org.junit.Test;

/**
 * Review S6: every ECDSA signature the SDK hands to the JDK has 0 &lt; r, s &lt; n first (CVE-2022-21449 class — a JDK
 * that accepted r = s = 0). A fresh P-256 key per run; the out-of-range forms never verify, whatever the JDK does.
 */
public class EcdsaRangeTest {

    static byte[] der(BigInteger r, BigInteger s) {
        return Der.seq(Der.integer(r), Der.integer(s));
    }

    @Test
    public void outOfRangeSignaturesNeverReachTheJdk() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair kp = g.generateKeyPair();
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        BigInteger n = pub.getParams().getOrder();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest("eid".getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Signature s = Signature.getInstance("NONEwithECDSA");
        s.initSign(kp.getPrivate());
        s.update(digest);
        byte[] good = s.sign();
        assertTrue(Sig.ecdsaDerInRange(pub, good));
        assertTrue(Sig.verify("NONEwithECDSA", pub, digest, good));
        assertTrue(Prehashed.verify(digest, Base64.getEncoder().encodeToString(good), pub, "ecdsa-with-SHA256", "SHA-256"));

        java.util.List<Der.Tlv> rs = Der.parse(good).children();
        BigInteger r = rs.get(0).bigInt();
        BigInteger sv = rs.get(1).bigInt();
        byte[][] bad = {
            der(BigInteger.ZERO, BigInteger.ZERO),
            der(BigInteger.ZERO, sv),
            der(r, BigInteger.ZERO),
            der(n, sv),
            der(r, n),
            der(r.add(n), sv),
            der(r.negate(), sv),
            Der.seq(Der.integer(r)),
            Der.seq(Der.integer(r), Der.integer(sv), Der.integer(BigInteger.ONE)),
            java.util.Arrays.copyOf(good, good.length + 1),
            new byte[0],
        };
        for (byte[] b : bad) {
            assertFalse(Sig.ecdsaDerInRange(pub, b));
            assertFalse(Sig.verify("NONEwithECDSA", pub, digest, b));
            assertFalse(Sig.verify("SHA256withECDSA", pub, digest, b));
            assertFalse(Prehashed.verify(digest, Base64.getEncoder().encodeToString(b), pub, "ecdsa-with-SHA256", "SHA-256"));
        }
        assertFalse(Sig.ecdsaInRange(pub, BigInteger.ZERO, BigInteger.ZERO));
        assertFalse(Sig.ecdsaInRange(pub, BigInteger.ONE, n));
        assertTrue(Sig.ecdsaInRange(pub, BigInteger.ONE, n.subtract(BigInteger.ONE)));
        // An ECDSA algorithm with a non-EC key never verifies.
        KeyPairGenerator rg = KeyPairGenerator.getInstance("RSA");
        rg.initialize(2048);
        assertFalse(Sig.verify("SHA256withECDSA", rg.generateKeyPair().getPublic(), digest, good));
    }
}
