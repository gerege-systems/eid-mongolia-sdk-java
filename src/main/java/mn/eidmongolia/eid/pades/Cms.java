package mn.eidmongolia.eid.pades;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** CMS SignedData (CAdES baseline, detached) — Go reference `pades/internal/core/cms.go`, byte for byte. */
final class Cms {
    static final String OID_DATA = "1.2.840.113549.1.7.1";
    static final String OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
    static final String OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
    static final String OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    static final String OID_SIGNING_CERT_V2 = "1.2.840.113549.1.9.16.2.47";
    static final String OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";
    static final String OID_SHA256 = "2.16.840.1.101.3.4.2.1";
    static final String OID_SHA256_RSA = "1.2.840.113549.1.1.11";
    static final String OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2";
    static final String OID_SIGNER_ATTR_V2 = "0.4.0.19122.1.1";
    static final String OID_ROLE = "2.5.4.72";
    static final int CLAIMED_ROLE_MAX_RUNES = 900;

    private Cms() {
    }

    static MessageDigest md(String name) {
        try {
            return MessageDigest.getInstance(name);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(name, e);
        }
    }

    static byte[] sha256(byte[] b) {
        return md("SHA-256").digest(b);
    }

    static byte[] sha1(byte[] b) {
        return md("SHA-1").digest(b);
    }

    /**
     * DER SET OF Attribute: contentType = id-data, messageDigest, signingCertificateV2 (+ signer-attributes-v2 with
     * claimedRole). No signingTime. Sorted by encoded bytes (X.690 §11.6).
     */
    static byte[] signedAttributes(byte[] messageDigest, Cert signer, String claimedRole) {
        if (messageDigest.length != 32) throw new IllegalArgumentException("messageDigest is not SHA-256");
        String role = claimedRole == null ? "" : claimedRole;
        if (!role.isEmpty()) {
            if (!Text.validSurrogates(role) || role.codePointCount(0, role.length()) > CLAIMED_ROLE_MAX_RUNES) {
                throw new IllegalArgumentException("claimed role");
            }
        }
        List<byte[]> attrs = new ArrayList<>();
        attrs.add(attr(OID_CONTENT_TYPE, Der.oid(OID_DATA)));
        attrs.add(attr(OID_MESSAGE_DIGEST, Der.octets(messageDigest)));
        attrs.add(attr(OID_SIGNING_CERT_V2,
            Der.seq( // SigningCertificateV2
                Der.seq( // certs
                    Der.seq( // ESSCertIDv2
                        Der.octets(sha256(signer.raw)),
                        Der.seq( // IssuerSerial
                            Der.seq(Der.tlv(Der.ctx(4), signer.rawIssuer)), // GeneralNames { directoryName [4] }
                            Der.integer(signer.serial)))))));
        if (!role.isEmpty()) {
            attrs.add(attr(OID_SIGNER_ATTR_V2,
                Der.seq(Der.tlv(Der.ctx(0),
                    Der.seq(Der.seq(Der.oid(OID_ROLE), Der.set(Der.tlv(Der.UTF8_STRING, Text.utf8(role)))))))));
        }
        attrs.sort(Der.BYTES_ORDER);
        return Der.set(attrs.toArray(new byte[0][]));
    }

    private static byte[] attr(String oid, byte[] value) {
        return Der.seq(Der.oid(oid), Der.set(value));
    }

    static byte[] dtbs(byte[] signedAttrs) {
        return sha256(signedAttrs);
    }

    private static byte[] algId(String oid, boolean nullParams) {
        return nullParams ? Der.seq(Der.oid(oid), Der.nullValue()) : Der.seq(Der.oid(oid));
    }

    /** ContentInfo{SignedData}: certificates = signer + chain (sorted), one SignerInfo, unsigned [1] = timestamp token. */
    static byte[] assemble(byte[] signedAttrs, Cert signer, List<Cert> chain, byte[] signature, byte[] tst) {
        if (signedAttrs.length < 2 || signedAttrs[0] != 0x31) throw new IllegalArgumentException("signedAttrs is not a DER SET");
        String sigAlg;
        if (signer.isRsa()) sigAlg = OID_SHA256_RSA;
        else if (signer.isEc()) sigAlg = OID_ECDSA_SHA256;
        else throw new IllegalArgumentException("unsupported signer key");
        byte[] implicitAttrs = signedAttrs.clone();
        implicitAttrs[0] = (byte) 0xA0;
        List<byte[]> certs = new ArrayList<>();
        certs.add(signer.raw);
        for (Cert c : chain) if (!c.equals(signer)) certs.add(c.raw);
        certs.sort(Der.BYTES_ORDER);
        byte[] signerInfo = Der.seq(
            Der.integer(1),
            Der.seq(signer.rawIssuer, Der.integer(signer.serial)),
            algId(OID_SHA256, false),
            implicitAttrs,
            algId(sigAlg, sigAlg.equals(OID_SHA256_RSA)),
            Der.octets(signature),
            tst != null && tst.length > 0
                ? Der.tlv(Der.ctx(1), Der.seq(Der.oid(OID_TIMESTAMP_TOKEN), Der.set(tst)))
                : new byte[0]);
        byte[] signedData = Der.seq(
            Der.integer(1),
            Der.set(algId(OID_SHA256, false)),
            Der.seq(Der.oid(OID_DATA)),
            Der.tlv(Der.ctx(0), Der.concat(certs.toArray(new byte[0][]))),
            Der.set(signerInfo));
        return Der.seq(Der.oid(OID_SIGNED_DATA), Der.tlv(Der.ctx(0), signedData));
    }

    /**
     * Go complete.go citizenSignature: verify over DTBS and return the CMS form — RSA PKCS#1 v1.5 as is; ECDSA r‖s
     * (2n bytes) → DER, or DER as is. Null when it does not verify.
     */
    static byte[] citizenSignature(Cert cert, byte[] dtbs, byte[] sig) {
        if (cert.isRsa()) return Sig.verify("NONEwithRSA", cert.publicKey(), digestInfoSha256(dtbs), sig) ? sig : null;
        if (cert.isEc()) {
            int bits = ((ECPublicKey) cert.publicKey()).getParams().getCurve().getField().getFieldSize();
            int n = (bits + 7) / 8;
            if (sig.length == 2 * n) {
                byte[] der = Der.seq(
                    Der.integer(new BigInteger(1, Arrays.copyOfRange(sig, 0, n))),
                    Der.integer(new BigInteger(1, Arrays.copyOfRange(sig, n, 2 * n))));
                if (Sig.verify("NONEwithECDSA", cert.publicKey(), dtbs, der)) return der;
            }
            return Sig.verify("NONEwithECDSA", cert.publicKey(), dtbs, sig) ? sig : null;
        }
        return null;
    }

    /** PKCS#1 v1.5 DigestInfo for SHA-256 (verify a pre-hashed DTBS with NONEwithRSA). */
    private static byte[] digestInfoSha256(byte[] h) {
        return Der.seq(algId(OID_SHA256, true), Der.octets(h));
    }

    // ── parsing (prior signatures, TSA tokens) ──

    static final class Parsed {
        final List<Cert> certificates;
        final Cert signer;
        final int signerCount;
        final String digestOid;
        final String sigOid;
        /** signedAttrs re-tagged as a DER SET (what the signature covers). */
        final byte[] signedAttrsSet;
        final byte[] messageDigest;
        final byte[] signature;
        /** eContent (TSTInfo for timestamp tokens), null when detached. */
        final byte[] eContent;
        final List<String> unsignedAttrOids;

        Parsed(List<Cert> certificates, Cert signer, int signerCount, String digestOid, String sigOid, byte[] signedAttrsSet,
               byte[] messageDigest, byte[] signature, byte[] eContent, List<String> unsignedAttrOids) {
            this.certificates = certificates;
            this.signer = signer;
            this.signerCount = signerCount;
            this.digestOid = digestOid;
            this.sigOid = sigOid;
            this.signedAttrsSet = signedAttrsSet;
            this.messageDigest = messageDigest;
            this.signature = signature;
            this.eContent = eContent;
            this.unsignedAttrOids = unsignedAttrOids;
        }
    }

    /** ContentInfo{SignedData} → the parts verification needs. */
    static Parsed parse(byte[] der) {
        Der.Tlv ci = Der.parse(der);
        if (ci.tag != Der.SEQUENCE || !ci.child(0).oid().equals(OID_SIGNED_DATA)) throw new IllegalArgumentException("not CMS SignedData");
        Der.Tlv sd = ci.child(1).child(0);
        List<Der.Tlv> f = sd.children();
        int i = 2; // version, digestAlgorithms
        Der.Tlv encap = f.get(i++);
        List<Der.Tlv> encapParts = encap.children();
        byte[] eContent = encapParts.size() > 1 ? encapParts.get(1).child(0).value() : null;
        List<Cert> certs = new ArrayList<>();
        if (f.get(i).tag == Der.ctx(0)) {
            for (Der.Tlv c : f.get(i).children()) if (c.tag == Der.SEQUENCE) certs.add(Cert.parse(c.encoded()));
            i++;
        }
        if (f.get(i).tag == Der.ctx(1)) i++; // crls
        List<Der.Tlv> infos = f.get(i).children();
        List<Der.Tlv> si = infos.get(0).children();
        int j = 1;
        Der.Tlv sid = si.get(j++);
        String digestOid = si.get(j++).child(0).oid();
        byte[] attrsSet = null;
        byte[] md = null;
        if (si.get(j).tag == Der.ctx(0)) {
            attrsSet = si.get(j++).encoded();
            attrsSet[0] = 0x31;
            for (Der.Tlv a : Der.parse(attrsSet).children()) {
                if (a.child(0).oid().equals(OID_MESSAGE_DIGEST)) md = a.child(1).child(0).value();
            }
        }
        String sigOid = si.get(j++).child(0).oid();
        byte[] signature = si.get(j++).value();
        List<String> unsigned = new ArrayList<>();
        if (j < si.size() && si.get(j).tag == Der.ctx(1)) {
            for (Der.Tlv a : si.get(j).children()) unsigned.add(a.child(0).oid());
        }
        Cert signer = null;
        for (Cert c : certs) {
            if (matchesSid(c, sid)) {
                signer = c;
                break;
            }
        }
        return new Parsed(certs, signer, infos.size(), digestOid, sigOid, attrsSet, md, signature, eContent,
            Collections.unmodifiableList(unsigned));
    }

    private static boolean matchesSid(Cert c, Der.Tlv sid) {
        if (sid.tag != Der.SEQUENCE) return false; // subjectKeyIdentifier [0] — not produced by eID / our TSA
        return Arrays.equals(c.rawIssuer, sid.child(0).encoded()) && c.serial.equals(sid.child(1).bigInt());
    }

    /** digitorus pkcs7 Verify (no chain): messageDigest = H(content) and the signature over signedAttrs. */
    static boolean verify(Parsed p, byte[] content) {
        Cert signer = p.signer;
        if (signer == null) return false;
        String alg = Sig.cmsAlgorithm(p.digestOid, p.sigOid);
        if (alg == null) return false;
        if (p.signedAttrsSet == null) return Sig.verify(alg, signer.publicKey(), content, p.signature);
        String dn = Sig.digestName(p.digestOid);
        if (dn == null) return false;
        byte[] h = md(dn).digest(content);
        if (p.messageDigest == null || !MessageDigest.isEqual(h, p.messageDigest)) return false;
        return Sig.verify(alg, signer.publicKey(), p.signedAttrsSet, p.signature);
    }
}
