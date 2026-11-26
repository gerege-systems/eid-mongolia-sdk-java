package mn.eidmongolia.eid.pades.validate;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;

/**
 * Trust decisions — TS src/pades/validate/evaluate.ts (CA validate.go / ltv.go, Go pades trust.go / validatepdf.go). The
 * chain is built like Go crypto/x509 Verify (parent order by key id, SHA-1 rejected, validity, EKU nesting), with the
 * SDK's fail-closed rule on top: a certificate carrying nameConstraints never takes part in a chain.
 */
final class Evaluate {
    static final String INTEGRITY = "integrity_failed";
    static final String MALFORMED = "malformed_signature";
    static final String WEAK = "weak_algorithm";
    static final String UNTRUSTED = "untrusted_chain";
    static final String KEY_USAGE = "wrong_key_usage";
    static final String REVOKED = "revoked";
    static final String REVOKED_AFTER = "revoked_after_signing";
    static final String REVOCATION_UNKNOWN = "revocation_unavailable";
    static final String EXPIRED = "expired";
    static final String NOT_YET_VALID = "not_yet_valid";
    static final String MODIFIED_AFTER = "modified_after_signing";
    static final String TIMESTAMP_INVALID = "timestamp_invalid";

    static final String KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
    static final String KP_OCSP_SIGNING = "1.3.6.1.5.5.7.3.9";
    static final String KP_ANY = "2.5.29.37.0";

    private Evaluate() {
    }

    static final class CertStatus {
        final boolean issued;
        final boolean revoked;
        final Instant revokedAt;

        CertStatus(boolean issued, boolean revoked, Instant revokedAt) {
            this.issued = issued;
            this.revoked = revoked;
            this.revokedAt = revokedAt;
        }
    }

    /** An online revocation check was interrupted: never swallowed as "no answer". */
    static final class Interrupted extends RuntimeException {
        private static final long serialVersionUID = 1L;

        Interrupted() {
            super("interrupted");
        }
    }

    private static void rethrowInterrupt(Exception e) {
        if (e instanceof java.io.InterruptedIOException || e instanceof Interrupted || Thread.currentThread().isInterrupted()) {
            throw new Interrupted();
        }
    }

    interface StatusSource {
        CertStatus certStatus(Cert cert, Cert issuer, Instant at) throws IOException;
    }

    static Instant notBefore(Cert c) {
        return Instant.ofEpochMilli(c.x509.getNotBefore().getTime());
    }

    static Instant notAfter(Cert c) {
        return Instant.ofEpochMilli(c.x509.getNotAfter().getTime());
    }

    private static boolean validAt(Cert c, Instant at) {
        return !Revocation.before(at, notBefore(c)) && !Revocation.after(at, notAfter(c));
    }

    // ── chain (Go crypto/x509 Verify) ──

    /** Go Certificate.CheckSignatureFrom (SHA-1 / MD5 rejected). */
    static boolean checkSigFrom(Cert c, Cert parent) {
        if (!parent.mayIssue(Cert.KU_CERT_SIGN)) return false;
        try {
            List<Asn1.Node> top = Asn1.children(Asn1.parseOne(c.raw));
            Asn1.Node alg = top.get(1);
            if (Revocation.SHA1_SIG.contains(Asn1.oid(Asn1.children(alg).get(0)))) return false;
            byte[] sb = top.get(2).value();
            if (sb.length == 0) return false;
            return VCrypto.verify(parent, alg, top.get(0).raw(), Arrays.copyOfRange(sb, 1, sb.length));
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static final Set<String> HANDLED_CRITICAL = Set.of("2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.17", "2.5.29.30", "2.5.29.32",
        "2.5.29.31", "2.5.29.35", "2.5.29.14", "2.5.29.36", "2.5.29.54", "2.5.29.33");

    /** An unknown critical extension, or (SDK fail-closed rule) any nameConstraints extension. */
    private static boolean unusable(Cert c) {
        for (String oid : c.criticalExtensionOids()) if (!HANDLED_CRITICAL.contains(oid)) return true;
        return c.extensionValue(Cert.OID_NAME_CONSTRAINTS) != null;
    }

    private static byte[] keyId(Cert c, String oid) {
        byte[] v = c.extensionValue(oid);
        if (v == null) return new byte[0];
        try {
            Asn1.Node n = Asn1.parseOne(v);
            if (oid.equals(Cert.OID_SKI)) return n.tag == Asn1.OCTET_STRING ? n.value() : new byte[0];
            for (Asn1.Node k : Asn1.children(n)) if (k.tag == 0x80) return k.value();
            return new byte[0];
        } catch (RuntimeException e) {
            return new byte[0];
        }
    }

    /** basicConstraints pathLenConstraint (-1 = absent). */
    private static int maxPathLen(Cert c) {
        byte[] v = c.extensionValue(Cert.OID_BASIC_CONSTRAINTS);
        if (v == null) return -1;
        try {
            for (Asn1.Node p : Asn1.children(Asn1.parseOne(v))) {
                if (p.tag == Asn1.INTEGER) {
                    java.math.BigInteger b = Asn1.intValue(p.value());
                    return b.bitLength() > 31 ? Integer.MAX_VALUE : b.intValue();
                }
            }
            return -1;
        } catch (RuntimeException e) {
            return -1;
        }
    }

    private static final class CertPool {
        final List<Cert> list = new ArrayList<>();

        void add(Cert c) {
            if (!contains(c)) list.add(c);
        }

        boolean contains(Cert c) {
            for (Cert x : list) if (Arrays.equals(x.raw, c.raw)) return true;
            return false;
        }

        /** Go findPotentialParents: AKID = SKID, then one missing, then mismatched. */
        List<Cert> parents(Cert c) {
            byte[] akid = keyId(c, Cert.OID_AKI);
            List<Cert> m = new ArrayList<>();
            List<Cert> one = new ArrayList<>();
            List<Cert> mis = new ArrayList<>();
            for (Cert p : list) {
                if (!Arrays.equals(p.rawSubject, c.rawIssuer)) continue;
                byte[] skid = keyId(p, Cert.OID_SKI);
                if (Arrays.equals(skid, akid)) m.add(p);
                else if ((skid.length == 0 && akid.length > 0) || (skid.length > 0 && akid.length == 0)) one.add(p);
                else mis.add(p);
            }
            m.addAll(one);
            m.addAll(mis);
            return m;
        }
    }

    private static void buildChains(List<Cert> chain, CertPool roots, CertPool inter, Instant at, int[] budget, List<List<Cert>> out) {
        Cert c = chain.get(chain.size() - 1);
        for (int pass = 0; pass < 2; pass++) {
            boolean root = pass == 0;
            for (Cert cand : (root ? roots : inter).parents(c)) {
                boolean loop = false;
                for (Cert x : chain) {
                    if (Arrays.equals(x.rawSubject, cand.rawSubject) && Arrays.equals(x.rawSubjectPublicKeyInfo, cand.rawSubjectPublicKeyInfo)) {
                        loop = true;
                        break;
                    }
                }
                if (loop) continue;
                if (++budget[0] > 100) continue;
                if (!checkSigFrom(c, cand)) continue;
                if (unusable(cand) || !validAt(cand, at)) continue;
                if (!root && (!cand.basicConstraintsValid() || !cand.isCa())) continue;
                int mpl = maxPathLen(cand);
                if (cand.basicConstraintsValid() && mpl >= 0 && chain.size() - 1 > mpl) continue;
                List<Cert> next = new ArrayList<>(chain);
                next.add(cand);
                if (root) out.add(next);
                else buildChains(next, roots, inter, at, budget, out);
            }
        }
    }

    /** Go checkChainForKeyUsage. */
    private static boolean chainAllows(List<Cert> chain, String eku) {
        for (int i = chain.size() - 1; i >= 0; i--) {
            List<String> e = chain.get(i).extKeyUsage();
            if (e.isEmpty() || e.contains(KP_ANY)) continue;
            if (!e.contains(eku)) return false;
        }
        return true;
    }

    // ── Evaluator ──

    static final class Evaluator {
        final List<Cert> roots;
        final List<Cert> intermediates;
        final List<Cert> issuers;
        final StatusSource status;
        final Instant now;
        private Instant lastRevokedAt;
        final Memo memo;

        Evaluator(List<Cert> roots, List<Cert> intermediates, List<Cert> issuers, StatusSource status, Instant now, Memo memo) {
            this.memo = memo;
            this.roots = roots;
            this.intermediates = intermediates;
            this.issuers = issuers;
            this.status = status;
            this.now = now;
        }

        private CertPool pool(List<Cert> extra) {
            CertPool p = new CertPool();
            for (Cert c : extra) p.add(c);
            for (Cert c : intermediates) p.add(c);
            return p;
        }

        /** The leaf up to a root at exactly [at] (eku "" = any). */
        List<Cert> verifyAt(Cert leaf, List<Cert> extra, Instant at, String eku) {
            if (roots.isEmpty()) return null;
            if (unusable(leaf) || !validAt(leaf, at)) return null;
            CertPool rp = new CertPool();
            for (Cert r : roots) rp.add(r);
            if (rp.contains(leaf)) return List.of(leaf);
            List<List<Cert>> chains = new ArrayList<>();
            buildChains(new ArrayList<>(List.of(leaf)), rp, pool(extra), at, new int[1], chains);
            if (eku.isEmpty()) return chains.isEmpty() ? null : chains.get(0);
            for (List<Cert> ch : chains) if (chainAllows(ch, eku)) return ch;
            return null;
        }

        List<Cert> verifyChain(Cert leaf, List<Cert> extra, Instant at) {
            List<Cert> ch = verifyAt(leaf, extra, at, "");
            if (ch != null) return ch;
            Instant nb = notBefore(leaf);
            Instant na = notAfter(leaf);
            if (Revocation.after(at, na) || Revocation.before(at, nb)) {
                long half = (leaf.x509.getNotAfter().getTime() - leaf.x509.getNotBefore().getTime()) / 2;
                return verifyAt(leaf, extra, nb.plusMillis(half), "");
            }
            return null;
        }

        private boolean isIssuer(Cert c) {
            for (Cert is : issuers) {
                if (Arrays.equals(c.rawSubject, is.rawSubject) && Arrays.equals(c.rawSubjectPublicKeyInfo, is.rawSubjectPublicKeyInfo)) return true;
            }
            return false;
        }

        PdfReport.CertInfo certInfo(Cert c, List<Cert> chain, Instant at) {
            PdfReport.CertInfo info = new PdfReport.CertInfo();
            info.commonName = GoFmt.commonName(c.rawSubject);
            info.subject = GoFmt.nameString(c.rawSubject);
            info.issuer = GoFmt.nameString(c.rawIssuer);
            info.serial = GoFmt.hexSerial(c.serial);
            info.notBefore = GoFmt.formatTime(notBefore(c));
            info.notAfter = GoFmt.formatTime(notAfter(c));
            info.usage = usageOf(c);
            info.revocation = new PdfReport.RevocationInfo("unknown", null);
            if (chain == null || chain.size() < 2 || !isIssuer(chain.get(1))) return info;
            info.issuedByEid = true;
            if (status == null) return info;
            CertStatus st;
            try {
                st = status.certStatus(c, chain.get(1), at);
            } catch (IOException | RuntimeException e) {
                rethrowInterrupt(e);
                return info;
            }
            if (!st.issued) return info;
            if (st.revoked) {
                info.revocation = new PdfReport.RevocationInfo("revoked", GoFmt.formatTime(st.revokedAt));
                lastRevokedAt = st.revokedAt;
            } else {
                info.revocation = new PdfReport.RevocationInfo("good", null);
            }
            return info;
        }

        private static final class Ts {
            PdfReport.TimestampInfo info;
            List<Cert> chain;
            boolean ok;
        }

        private Ts evaluateTimestamp(Extract.RawTimestamp r) {
            Ts out = new Ts();
            out.info = new PdfReport.TimestampInfo(GoFmt.formatTime(r.time), r.serial, "", false);
            Cert tsa;
            try {
                tsa = VCrypto.cert(r.tsaCert == null ? new byte[0] : r.tsaCert);
            } catch (RuntimeException e) {
                return out;
            }
            out.info.tsa = GoFmt.commonName(tsa.rawSubject);
            if (!r.matches || r.weakDigest || GoFmt.isZero(r.time) || !tsa.isTsaSigningCert()) return out;
            out.chain = verifyAt(tsa, parseCerts(r.certs), r.time, KP_TIMESTAMPING);
            out.info.trusted = out.chain != null;
            out.ok = out.info.trusted;
            return out;
        }

        PdfReport.SignatureReport evaluateSignature(Extract.RawSignature r) {
            PdfReport.SignatureReport s = new PdfReport.SignatureReport();
            s.coversWholeDocument = r.coversWhole;
            s.visible = r.visible;
            if (!r.signerName.isEmpty()) s.claimedName = r.signerName;
            if (!r.reason.isEmpty()) s.reason = r.reason;
            if (!r.location.isEmpty()) s.location = r.location;
            if (r.claimedTime != null) s.claimedTime = GoFmt.formatTime(r.claimedTime);
            if (!r.claimedRoles.isEmpty()) s.claimedRoles = new ArrayList<>(r.claimedRoles);
            if (!r.coversWhole && r.laterSignaturesOnly) {
                s.extendedBySignaturesOnly = true;
                s.laterSignatures = r.laterSignatures;
                s.visibleLaterSignature = r.laterVisible;
            }
            if (r.malformed) return fail(s, MALFORMED);
            Cert leaf;
            try {
                leaf = VCrypto.cert(r.leaf == null ? new byte[0] : r.leaf);
            } catch (RuntimeException e) {
                return fail(s, MALFORMED);
            }
            s.signerName = displayName(leaf);
            s.signerNameSource = "certificate";
            String civil = civilId(leaf);
            if (!civil.isEmpty()) s.civilId = civil;
            if (!r.integrity) return fail(s, INTEGRITY);
            if (r.weakDigest) return fail(s, WEAK);
            boolean cades = r.subFilter.equals("ETSI.CAdES.detached");
            if (cades && !r.signingCertV2.equals("match")) return fail(s, MALFORMED);

            Instant at = now;
            Instant signingTime = null;
            List<Cert> tsChain = null;
            if (r.timestamp != null) {
                Ts ts = evaluateTimestamp(r.timestamp);
                tsChain = ts.chain;
                s.timestamp = ts.info;
                if (ts.ok) {
                    signingTime = r.timestamp.time;
                    s.signingTime = GoFmt.formatTime(signingTime);
                    at = signingTime;
                } else {
                    s.problems.add(TIMESTAMP_INVALID);
                }
            }

            List<Cert> chain = verifyChain(leaf, parseCerts(r.certs), at);
            boolean trusted = chain != null;
            s.chainTrusted = trusted;
            s.chain = new ArrayList<>();
            if (chain != null) for (Cert c : chain) s.chain.add(GoFmt.commonName(c.rawSubject));
            else s.chain.add(GoFmt.commonName(leaf.rawSubject));
            lastRevokedAt = null;
            PdfReport.CertInfo info = certInfo(leaf, chain, at);
            s.certificate = info;
            if (!trusted) s.problems.add(UNTRUSTED);
            if (!(info.usage.equals("sign") || info.usage.equals("seal") || info.usage.equals("document_signer"))) s.problems.add(KEY_USAGE);
            if (Revocation.after(at, notAfter(leaf))) s.problems.add(EXPIRED);
            else if (Revocation.before(at, notBefore(leaf))) s.problems.add(NOT_YET_VALID);
            if (info.revocation.status.equals("revoked")) {
                Instant ra = lastRevokedAt;
                if (signingTime != null && ra != null && Revocation.after(ra, signingTime)) s.problems.add(REVOKED_AFTER);
                else s.problems.add(REVOKED);
            } else if (info.revocation.status.equals("unknown") && trusted) {
                s.problems.add(REVOCATION_UNKNOWN);
            }
            // SDK rule (as .NET): a platform-attested name only for a document covered or extended only by signatures.
            boolean unmodified = r.coversWhole || r.laterSignaturesOnly;
            if (trusted && unmodified && info.issuedByEid && info.usage.equals("document_signer") && !s.problems.contains(REVOKED)) {
                s.signerName = r.signerName;
                s.signerNameSource = "platform_attested";
            }
            if (cades && r.signingTimeAttr && info.issuedByEid) s.problems.add(MALFORMED);
            if (!r.coversWhole && !r.laterSignaturesOnly) s.problems.add(MODIFIED_AFTER);
            if (trusted) {
                List<List<Cert>> chains = new ArrayList<>();
                chains.add(chain);
                chains.add(tsChain == null ? List.of() : tsChain);
                s.ltv = ltvCoverage(r.dss, at, now, chains, memo);
            }
            if (cades) {
                s.signatureLevel = signingTime != null && s.ltv != null && s.ltv.complete ? "PAdES-BASELINE-LT"
                    : signingTime != null ? "PAdES-BASELINE-T" : "PAdES-BASELINE-B";
            }
            s.indication = indication(s.problems);
            return s;
        }

        private static PdfReport.SignatureReport fail(PdfReport.SignatureReport s, String p) {
            s.problems.add(p);
            s.indication = "invalid";
            return s;
        }
    }

    static String indication(List<String> problems) {
        String out = "valid";
        for (String p : problems) {
            switch (p) {
                case INTEGRITY:
                case MALFORMED:
                case WEAK:
                case UNTRUSTED:
                case KEY_USAGE:
                case REVOKED:
                case EXPIRED:
                case NOT_YET_VALID:
                    return "invalid";
                case REVOKED_AFTER:
                    break;
                default:
                    out = "indeterminate";
            }
        }
        return out;
    }

    static List<Cert> parseCerts(List<byte[]> ders) {
        List<Cert> out = new ArrayList<>();
        for (byte[] d : ders) {
            try {
                out.add(VCrypto.cert(d));
            } catch (RuntimeException e) {
                // skipped
            }
        }
        return out;
    }

    /** eidcrypto.SubjectDisplayName. */
    static String displayName(Cert c) {
        String[] n = GoFmt.subjectNames(c.rawSubject);
        String s = mn.eidmongolia.eid.internal.Text.trimSpace(n[0] + " " + n[1]);
        return !s.isEmpty() ? s : GoFmt.commonName(c.rawSubject);
    }

    private static String civilId(Cert c) {
        String sn = GoFmt.subjectSerialNumber(c.rawSubject);
        return sn.startsWith("PNOMN-") ? sn.substring(6) : "";
    }

    private static final String EKU_DOCUMENT_SIGNING = "1.3.6.1.5.5.7.3.36";
    private static final Set<String> GO_KNOWN_EKU = Set.of("2.5.29.37.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7", "1.3.6.1.5.5.7.3.8", "1.3.6.1.5.5.7.3.9",
        "1.3.6.1.4.1.311.10.3.3", "2.16.840.1.113730.4.1", "1.3.6.1.4.1.311.2.1.22", "1.3.6.1.4.1.311.61.1.1");

    /** CA usageOf: the profile by KU / EKU. */
    static String usageOf(Cert c) {
        List<String> ekus = c.extKeyUsage();
        List<String> known = new ArrayList<>();
        for (String e : ekus) if (GO_KNOWN_EKU.contains(e)) known.add(e);
        for (String e : known) {
            if (e.equals(KP_TIMESTAMPING)) return "timestamp";
            if (e.equals(KP_OCSP_SIGNING)) return "other";
        }
        if (c.isCa()) return "other";
        if (ekus.contains(EKU_DOCUMENT_SIGNING)) return "document_signer";
        int ku = Extract.keyUsage(c);
        boolean cc = (ku & 2) != 0;
        boolean ds = (ku & 1) != 0;
        if (cc && !ds && known.isEmpty()) return "seal";
        if (cc) return "sign";
        if (ds && known.contains("1.3.6.1.5.5.7.3.2")) return "auth";
        return "other";
    }

    // ── LTV (ltv.go) ──

    private static final String OID_OCSP_NOCHECK = "1.3.6.1.5.5.7.48.1.5";

    /** Go ltvCoverage. */
    static PdfReport.LtvInfo ltvCoverage(Extract.RawDss dss, Instant at, Instant now, List<List<Cert>> chains, Memo memo) {
        PdfReport.LtvInfo out = new PdfReport.LtvInfo();
        List<Revocation.Crl> crls = new ArrayList<>();
        if (dss != null) {
            for (byte[] der : dss.crls) {
                Revocation.Crl c = memo.crl(der);
                if (c != null) crls.add(c);
            }
        }
        List<byte[]> seen = new ArrayList<>();
        for (List<Cert> chain : chains) {
            for (int i = 0; i + 1 < chain.size(); i++) {
                Cert cert = chain.get(i);
                Cert issuer = chain.get(i + 1);
                boolean dup = false;
                for (byte[] x : seen) if (Arrays.equals(x, cert.raw)) dup = true;
                if (dup) continue;
                seen.add(cert.raw);
                if (!covered(cert, issuer, at, now, dss == null ? List.of() : dss.ocsps, crls, memo)) out.missing.add(GoFmt.commonName(cert.rawSubject));
            }
        }
        out.complete = out.missing.isEmpty() && !seen.isEmpty();
        return out;
    }

    private static boolean covered(Cert cert, Cert issuer, Instant at, Instant now, List<byte[]> ocsps, List<Revocation.Crl> crls, Memo memo) {
        for (byte[] der : ocsps) {
            Revocation.OcspResp resp = memo.parseOcsp(der, cert, issuer);
            if (resp == null) continue;
            if (!resp.status.equals("good") || !memo.certIdMatches(der, cert, issuer)) continue;
            if (resp.certificate != null && !Arrays.equals(resp.certificate.raw, issuer.raw)
                && resp.certificate.extensionValue(OID_OCSP_NOCHECK) == null) {
                continue;
            }
            if (Revocation.ocspFreshAt(resp, at, now)) return true;
        }
        for (Revocation.Crl crl : crls) {
            if (!memo.crlFor(crl, cert, issuer) || !Revocation.freshAt(crl.thisUpdate, crl.nextUpdate, at, now)) continue;
            if (Revocation.crlListed(crl, cert) != null) continue;
            return true;
        }
        return false;
    }

    // ── revocation sources ──

    private static boolean responderOk(Revocation.OcspResp resp, Cert issuer) {
        if (resp.certificate == null || Arrays.equals(resp.certificate.raw, issuer.raw)) return true;
        return resp.certificate.extKeyUsage().contains(KP_OCSP_SIGNING);
    }

    /** Go ocspFor: der is cert's response (CertID = issuer + serial), signed by the issuer or its OCSPSigning responder. */
    private static Revocation.OcspResp ocspFor(byte[] der, Cert cert, Cert issuer) {
        Revocation.OcspResp resp;
        try {
            resp = Revocation.parseOcspFrom(der, cert.serial, issuer);
        } catch (RuntimeException e) {
            return null;
        }
        if (!resp.serial.equals(cert.serial) || !Revocation.ocspCertIdMatches(der, cert, issuer) || !responderOk(resp, issuer)) return null;
        return resp;
    }

    /** Go dssStatus: from the document's DSS. Any revoked evidence wins (earliest time); else fresh good; else not issued. */
    static final class DssStatus implements StatusSource {
        private final Extract.RawDss dss;
        private final Instant now;

        private final Memo memo;

        DssStatus(Extract.RawDss dss, Instant now, Memo memo) {
            this.memo = memo;
            this.dss = dss;
            this.now = now;
        }

        @Override
        public CertStatus certStatus(Cert cert, Cert issuer, Instant at) {
            Instant revoked = null;
            boolean good = false;
            if (dss != null) {
                for (byte[] der : dss.ocsps) {
                    Revocation.OcspResp resp = memo.ocspFor(der, cert, issuer);
                    if (resp == null) continue;
                    if (resp.status.equals("revoked")) {
                        if (revoked == null || Revocation.before(resp.revokedAt, revoked)) revoked = resp.revokedAt;
                    } else if (resp.status.equals("good")) {
                        good |= Revocation.ocspFreshAt(resp, at, now);
                    }
                }
                for (byte[] der : dss.crls) {
                    Revocation.Crl crl = memo.crl(der);
                    if (crl == null || !memo.crlFor(crl, cert, issuer)) continue;
                    Instant t = Revocation.crlListed(crl, cert);
                    if (t != null) {
                        if (revoked == null || Revocation.before(t, revoked)) revoked = t;
                    } else {
                        good |= Revocation.freshAt(crl.thisUpdate, crl.nextUpdate, at, now);
                    }
                }
            }
            if (revoked != null) return new CertStatus(true, true, revoked);
            if (good) return new CertStatus(true, false, null);
            return new CertStatus(false, false, null);
        }
    }

    static final int ONLINE_OCSP_MAX = 16 << 10;

    /** Go onlineStatus: AIA OCSP, else CDP CRL (current status, fresh at now); no answer → the fallback (DSS). */
    static final class OnlineStatus implements StatusSource {
        private final Fetch f;
        private final StatusSource fallback;
        private final Instant now;
        private final Map<String, CertStatus> cache = new HashMap<>();

        OnlineStatus(Fetch f, StatusSource fallback, Instant now) {
            this.f = f;
            this.fallback = fallback;
            this.now = now;
        }

        @Override
        public CertStatus certStatus(Cert cert, Cert issuer, Instant at) throws IOException {
            String key = Text.hex(cert.raw) + ":" + Text.hex(issuer.raw);
            CertStatus hit = cache.get(key);
            if (hit != null) return hit;
            CertStatus st = ocsp(cert, issuer);
            if (st == null) st = crl(cert, issuer);
            if (fallback != null && (st == null || !st.revoked)) {
                CertStatus fst = fallback.certStatus(cert, issuer, at);
                if (st == null || fst.revoked) st = fst;
            }
            if (st == null) st = new CertStatus(false, false, null);
            cache.put(key, st);
            return st;
        }

        private CertStatus ocsp(Cert cert, Cert issuer) {
            byte[] req;
            try {
                req = Revocation.ocspRequest(cert, issuer);
            } catch (RuntimeException e) {
                return null;
            }
            for (String u : cert.ocspServers()) {
                byte[] der;
                try {
                    der = f.send("POST", u, "application/ocsp-request", req);
                } catch (IOException | RuntimeException e) {
                    rethrowInterrupt(e);
                    continue;
                }
                if (der.length > ONLINE_OCSP_MAX) continue;
                Revocation.OcspResp resp = ocspFor(der, cert, issuer);
                if (resp == null) continue;
                Cert rc = resp.certificate;
                if (rc != null && !Revocation.sameCertKey(rc, issuer) && !validAt(rc, now)) continue;
                if (resp.status.equals("revoked")) return new CertStatus(true, true, resp.revokedAt);
                if (!Revocation.ocspFreshAt(resp, now, now)) continue;
                if (resp.status.equals("good")) return new CertStatus(true, false, null);
                return new CertStatus(false, false, null);
            }
            return null;
        }

        private CertStatus crl(Cert cert, Cert issuer) {
            for (String u : cert.crlDistributionPoints()) {
                Revocation.Crl crl;
                try {
                    crl = Revocation.parseCrl(f.send("GET", u, null, null));
                } catch (IOException | RuntimeException e) {
                    rethrowInterrupt(e);
                    continue;
                }
                if (crl == null || !Revocation.crlFor(crl, cert, issuer)) continue;
                Instant t = Revocation.crlListed(crl, cert);
                if (t != null) return new CertStatus(true, true, t);
                if (Revocation.freshAt(crl.thisUpdate, crl.nextUpdate, now, now)) return new CertStatus(true, false, null);
            }
            return null;
        }
    }

    /**
     * Per-validation cache of DSS evidence work: each OCSP / CRL item is parsed and its signature verified once per
     * (item, certificate, issuer), however many signatures and chain positions ask (bounded CPU on hostile documents).
     */
    static final class Memo {
        private static final class Key {
            final Object item;
            final Object crl;
            final Cert cert;
            final Cert issuer;

            Key(Object item, Object crl, Cert cert, Cert issuer) {
                this.item = item;
                this.crl = crl;
                this.cert = cert;
                this.issuer = issuer;
            }

            @Override
            public boolean equals(Object o) {
                if (!(o instanceof Key)) return false;
                Key k = (Key) o;
                return item == k.item && crl == k.crl && java.util.Objects.equals(cert, k.cert) && java.util.Objects.equals(issuer, k.issuer);
            }

            @Override
            public int hashCode() {
                return java.util.Objects.hash(System.identityHashCode(item), System.identityHashCode(crl), cert, issuer);
            }
        }

        private static final Object NONE = new Object();
        private final Map<byte[], Object> crls = new java.util.IdentityHashMap<>();
        private final Map<Key, Object> parsed = new HashMap<>();
        private final Map<Key, Object> fors = new HashMap<>();
        private final Map<Key, Boolean> ids = new HashMap<>();
        private final Map<Key, Boolean> crlFors = new HashMap<>();

        Revocation.Crl crl(byte[] der) {
            Object v = crls.computeIfAbsent(der, d -> {
                Revocation.Crl c = Revocation.parseCrl(d);
                return c == null ? NONE : c;
            });
            return v == NONE ? null : (Revocation.Crl) v;
        }

        boolean crlFor(Revocation.Crl crl, Cert cert, Cert issuer) {
            return crlFors.computeIfAbsent(new Key(null, crl, cert, issuer), k -> Revocation.crlFor(crl, cert, issuer));
        }

        /** parseOcsp(der, cert.serial, issuer), or null on any failure. */
        Revocation.OcspResp parseOcsp(byte[] der, Cert cert, Cert issuer) {
            Object v = parsed.computeIfAbsent(new Key(der, null, cert, issuer), k -> {
                try {
                    return Revocation.parseOcsp(der, cert.serial, issuer);
                } catch (RuntimeException e) {
                    return NONE;
                }
            });
            return v == NONE ? null : (Revocation.OcspResp) v;
        }

        boolean certIdMatches(byte[] der, Cert cert, Cert issuer) {
            return ids.computeIfAbsent(new Key(der, null, cert, issuer), k -> Revocation.ocspCertIdMatches(der, cert, issuer));
        }

        Revocation.OcspResp ocspFor(byte[] der, Cert cert, Cert issuer) {
            Object v = fors.computeIfAbsent(new Key(der, null, cert, issuer), k -> {
                Revocation.OcspResp r = Evaluate.ocspFor(der, cert, issuer);
                return r == null ? NONE : r;
            });
            return v == NONE ? null : (Revocation.OcspResp) v;
        }
    }

    // ── level (eid.CertificateLevelOf) ──

    private static final String OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3";
    private static final String OID_QC_COMPLIANCE = "0.4.0.1862.1.1";
    private static final String OID_QC_SSCD = "0.4.0.1862.1.4";

    /** qcStatements QcCompliance → QUALIFIED (+ QcSSCD → QSCD), else ADVANCED; null when malformed. */
    static String signLevelOf(Cert c) {
        byte[] v = c.extensionValue(OID_QC_STATEMENTS);
        if (v == null) return "ADVANCED";
        try {
            Asn1.Node seq = Asn1.parseOne(v);
            if (seq.tag != Asn1.SEQUENCE) return null;
            boolean compliance = false;
            boolean sscd = false;
            for (Asn1.Node st : Asn1.children(seq)) {
                if (st.tag != Asn1.SEQUENCE) return null;
                Asn1.Node id = Asn1.readNode(st.buf, st.vs, st.end);
                if (id.tag != Asn1.OID) return null;
                String o = Asn1.oid(id);
                compliance |= o.equals(OID_QC_COMPLIANCE);
                sscd |= o.equals(OID_QC_SSCD);
            }
            return !compliance ? "ADVANCED" : sscd ? "QSCD" : "QUALIFIED";
        } catch (RuntimeException e) {
            return null;
        }
    }
}
