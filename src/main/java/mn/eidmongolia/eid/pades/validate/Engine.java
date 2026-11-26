package mn.eidmongolia.eid.pades.validate;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CancellationException;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.pades.EidPadesTransport;

/**
 * INTERNAL — not part of the SDK's API; call {@code EidPades.validatePdf}. The ValidatePDF pipeline (TS src/validate.ts
 * validatePdf): extract → revocation source (DSS, then online unless offline) → evaluate each signature → certificate
 * level, key medium, overall indication. Public only because Java has no cross-package internal visibility.
 *
 * <p>Errors other than {@link ValidatePdfException}: an {@link OutOfMemoryError} (or any other Error but a stack overflow)
 * propagates unchanged; an interrupted online check restores the interrupt flag and throws {@link CancellationException}.
 */
public final class Engine {
    private Engine() {
    }

    private static final String[] CHAIN = {"01-mongolian-national-root-ca.pem", "02-mongolian-national-issuing-ca-mddc.pem",
        "03-gerege-issuing-ca.pem", "04-eid-mongolia-issuing-ca.pem", "05-eid-mongolia-org-issuing-ca.pem"};

    private static Cert embedded(String name) {
        try (InputStream s = Engine.class.getResourceAsStream("/mn/eidmongolia/eid/pades/chain/" + name)) {
            if (s == null) throw new IllegalStateException("missing resource " + name);
            return Cert.parse(Cert.pemSingle(s.readAllBytes()));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<Cert> ders(List<byte[]> list, String what) {
        List<Cert> out = new ArrayList<>();
        for (byte[] d : list) {
            try {
                out.add(Cert.parse(d));
            } catch (RuntimeException e) {
                throw new ValidatePdfException(ValidatePdfException.REQUEST_INVALID, what + ": certificate does not parse");
            }
        }
        return out;
    }

    private static ValidatePdfException invalid() {
        return new ValidatePdfException(ValidatePdfException.PDF_INVALID, "the PDF does not parse");
    }

    /** INTERNAL entry point (see the class comment). */
    public static PdfReport run(byte[] pdf, ValidatePdfOptions opts, PadesSupport support, EidPadesTransport defaultTransport) {
        if (pdf.length > Extract.MAX_PDF_BYTES) throw new ValidatePdfException(ValidatePdfException.PDF_TOO_LARGE, "PDF larger than 10 MiB");
        List<Cert> roots = opts.roots.isEmpty() ? List.of(embedded(CHAIN[0])) : ders(opts.roots, "roots");
        List<Cert> inter = new ArrayList<>();
        for (int i = 1; i < CHAIN.length; i++) inter.add(embedded(CHAIN[i]));
        inter.addAll(ders(opts.intermediates, "intermediates"));
        List<Cert> issuers = new ArrayList<>(List.of(embedded(CHAIN[3]), embedded(CHAIN[4])));
        issuers.addAll(ders(opts.issuers, "issuers"));
        Extract.Extracted ex;
        try {
            ex = Extract.extract(pdf, support);
        } catch (Extract.Failure e) {
            switch (e.code) {
                case "no_signature":
                    throw new ValidatePdfException(ValidatePdfException.PDF_NO_SIGNATURE, "the document has no signature");
                case "too_many":
                    throw new ValidatePdfException(ValidatePdfException.PDF_TOO_MANY_SIGNATURES, "the document has too many signatures");
                case "encrypted":
                    throw new ValidatePdfException(ValidatePdfException.PDF_ENCRYPTED, "an encrypted PDF cannot be validated");
                default:
                    throw invalid();
            }
        } catch (RuntimeException | StackOverflowError e) {
            throw invalid();
        }
        Instant now = opts.time != null ? opts.time : Instant.now();
        Extract.RawDss dss = null;
        for (Extract.RawSignature s : ex.sigs) {
            if (s.dss != null) {
                dss = s.dss;
                break;
            }
        }
        Evaluate.Memo memo = new Evaluate.Memo();
        Evaluate.StatusSource status = new Evaluate.DssStatus(dss, now, memo);
        if (!opts.offline) {
            EidPadesTransport t = opts.transport != null ? opts.transport : defaultTransport;
            status = new Evaluate.OnlineStatus(new Fetch(t), status, now);
        }
        Evaluate.Evaluator ev = new Evaluate.Evaluator(roots, inter, issuers, status, now, memo);
        PdfReport rep = new PdfReport();
        // Identical signature dictionaries (same ByteRange, CMS and report-relevant facts) are evaluated once.
        Map<String, PdfReport.SignatureReport> seen = new HashMap<>();
        try {
            for (Extract.RawSignature r : ex.sigs) {
                String key = sameKey(r);
                PdfReport.SignatureReport s = seen.get(key);
                if (s == null) {
                    s = ev.evaluateSignature(r);
                    if (s.chainTrusted && r.leaf != null) {
                        String lvl = Evaluate.signLevelOf(VCrypto.cert(r.leaf));
                        if (lvl != null) s.certificateLevel = lvl;
                    }
                    s.keyMedium = keyMedium(s);
                    seen.put(key, s);
                }
                rep.signatures.add(s);
            }
        } catch (Evaluate.Interrupted e) {
            Thread.currentThread().interrupt();
            throw new CancellationException("validation interrupted");
        } catch (RuntimeException | StackOverflowError e) {
            // Defence in depth: evaluation never escapes untyped (no case of the corpus reaches here).
            throw invalid();
        }
        for (PdfReport.SignatureReport s : rep.signatures) {
            if (s.indication.equals("invalid")) {
                rep.indication = "invalid";
                break;
            }
            if (s.indication.equals("indeterminate")) rep.indication = "indeterminate";
        }
        return rep;
    }

    /** Everything evaluateSignature reads from a RawSignature but the object number. */
    private static String sameKey(Extract.RawSignature r) {
        return Arrays.toString(r.byteRange) + "|" + r.cmsSha256 + "|" + r.messageDigest + "|" + r.malformed + "|" + r.integrity + "|"
            + r.weakDigest + "|" + r.coversWhole + "|" + r.laterSignaturesOnly + "|" + r.laterSignatures + "|" + r.laterVisible + "|"
            + r.visible + "|" + r.subFilter + "|" + r.signingCertV2 + "|" + r.signingTimeAttr + "|" + r.claimedRoles + "|" + r.claimedTime
            + "|" + r.signerName.length() + ":" + r.signerName + "|" + r.reason.length() + ":" + r.reason + "|" + r.location.length() + ":"
            + r.location + "|" + (r.dss == null ? 0 : System.identityHashCode(r.dss)) + "|" + (r.leaf == null ? "" : Arrays.hashCode(r.leaf));
    }

    /** Locally only from the certificate: an eID SIGN certificate with QcCompliance → "phone", else "unknown". */
    private static String keyMedium(PdfReport.SignatureReport s) {
        PdfReport.CertInfo c = s.certificate;
        if (c != null && c.issuedByEid && c.usage.equals("sign")
            && ("QUALIFIED".equals(s.certificateLevel) || "QSCD".equals(s.certificateLevel))) {
            return "phone";
        }
        return "unknown";
    }
}
