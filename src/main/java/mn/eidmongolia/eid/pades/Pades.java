package mn.eidmongolia.eid.pades;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.function.LongConsumer;
import java.util.function.Supplier;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;

/**
 * Native signing path — Go reference `pades/prepare.go` + `pades/complete.go` (profile pades-client/1) without the
 * revision validator (native SDKs do light prechecks only; full verification is the Go backend SDK).
 */
final class Pades {
    static final String PROFILE = "pades-client/1";
    static final int MAX_INPUT_BYTES = (10 << 20) - (256 << 10);
    static final int MAX_OUTPUT_BYTES = 10 << 20;
    private static final int MAX_FILE_NAME = 120;
    static final String DEFAULT_TSA_URL = "https://tsa.timeserver.mn/";
    private static final String PAGE_BRAND = "eID Mongolia";
    private static final String PAGE_PROVIDER = "ca.eidmongolia.mn";
    private static final String PAGE_TRUST_URL = "https://eidmongolia.mn/trust";
    private static final String PAGE_TSA_NAME = "eID Mongolia TSA (tsa.timeserver.mn)";

    private Pades() {
    }

    /** Clock / sleep / nonce — fixed in conformance tests (Go: Now, sleepFn, nonceReader). */
    static final class Env {
        final Supplier<Date> now;
        final LongConsumer sleep;
        final Supplier<byte[]> nonce;

        Env(Supplier<Date> now, LongConsumer sleep, Supplier<byte[]> nonce) {
            this.now = now;
            this.sleep = sleep;
            this.nonce = nonce;
        }

        static Env system() {
            return new Env(Date::new, ms -> {
                if (ms <= 0) return;
                try {
                    Thread.sleep(ms);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("interrupted", e);
                }
            }, () -> {
                byte[] b = new byte[8];
                new SecureRandom().nextBytes(b);
                return b;
            });
        }
    }

    private static boolean notEmpty(String s) {
        return s != null && !s.isEmpty();
    }

    private static void checkHeader(byte[] doc) {
        if (doc.length > MAX_INPUT_BYTES) throw new EidPadesException.PdfTooLarge("PDF larger than 9.75 MiB");
        if (doc.length < 5 || !new String(doc, 0, 5, StandardCharsets.ISO_8859_1).equals("%PDF-")) {
            throw new EidPadesException.PdfInvalid("not a PDF or damaged");
        }
        try {
            Structure.check(doc);
        } catch (Structure.Failure e) {
            throw new EidPadesException.PdfInvalid("PDF structure nested too deep or too complex");
        }
    }

    static Prepared prepare(byte[] doc, PrepareOptions o) {
        checkHeader(doc);
        Cert cert;
        try {
            cert = Cert.parse(o.signerCertRaw());
        } catch (Exception e) {
            throw new EidPadesException.SignerInvalid("signerCert: " + e.getMessage());
        }
        if (!cert.isRsa() && !cert.isEc()) throw new EidPadesException.SignerInvalid("unsupported signer key type");
        List<Cert> chain = signerChain(cert, o.chain());
        if (notEmpty(o.docId()) && !Precheck.UUID_RE.matcher(o.docId()).matches()) {
            throw new EidPadesException.RequestInvalid("docId must be a lowercase UUID");
        }
        if (notEmpty(o.lang()) && !o.lang().equals("mn") && !o.lang().equals("en")) throw new EidPadesException.RequestInvalid("lang: mn | en");
        String pos = o.verifyPagePosition();
        if (notEmpty(pos) && !pos.equals("last") && !pos.equals("first")) {
            throw new EidPadesException.RequestInvalid("verifyPagePosition: last | first");
        }
        boolean first = "first".equals(pos);
        checkAppearance(o.appearance(), o.claimedRole());
        Date now = o.signingTime() != null ? o.signingTime() : new Date();
        String inHex = Text.hex(Cms.sha256(doc));
        String fileName = cleanFileName(o.fileName());
        List<Cert> issuers = new ArrayList<>(EidChain.issuers());
        issuers.add(chain.get(0));
        Precheck.Result pre = Precheck.run(doc, issuers);
        boolean seal = mn.eidmongolia.eid.SealService.isSealCertificate(cert.raw);
        // A stamp with QR: the citizen stamp (§3) or the seal stamp with QR (§6.5).
        boolean drawsQr = o.appearance() != null && (!seal || o.sealQr());
        String docId = resolveDocId(doc, pre, o.docId());
        boolean hasPage = pre.newDoc && o.verifyPage();
        byte[] base = doc;
        String pageHex = null;
        if (hasPage) {
            if (fileName == null) throw new EidPadesException.RequestInvalid("fileName required, ≤ 120 characters");
            String id = docId;
            try {
                base = VerifyPage.append(doc, new VerifyPage.Data(PAGE_BRAND, fileName, inHex, doc.length, id, Precheck.VERIFY_URL + id,
                    PAGE_TRUST_URL, cert.issuerCommonName(), PAGE_TSA_NAME, PAGE_PROVIDER, o.lang()), first);
            } catch (Exception e) {
                throw new EidPadesException.PdfInvalid("cannot append the verify page: " + e.getMessage());
            }
            pageHex = Text.hex(Cms.sha256(base));
        }
        String name = o.signerName() != null && !Text.trimSpace(o.signerName()).isEmpty() ? o.signerName() : cert.displayName();
        Appearance.Visible vis = o.appearance() != null ? visibleSpec(doc, o, name, now, docId == null ? "" : docId, pre.revIndex, seal, drawsQr)
            : null;
        // vis.page counts the input's pages; a verify page added in front shifts them by one in base (PLACEMENT_SPEC §1b).
        Appearance.Visible onBase = vis != null && hasPage && first ? vis.onPage(vis.page + 1) : vis;
        SignatureRevision.Prepared prep;
        try {
            prep = SignatureRevision.prepare(base, now, name, o.reason(), onBase);
        } catch (AppearanceException e) {
            throw new EidPadesException.RequestInvalid("appearance: " + e.getMessage());
        } catch (Exception e) {
            throw new EidPadesException.PdfInvalid("cannot write the signature revision: " + e.getMessage());
        }
        if (prep.pdf.length + (256 << 10) > MAX_OUTPUT_BYTES) throw new EidPadesException.PdfTooLarge("signed output would exceed 10 MiB");
        byte[] attrs;
        try {
            attrs = Cms.signedAttributes(prep.digest, cert, o.claimedRole());
        } catch (Exception e) {
            throw new EidPadesException.RequestInvalid("claimedRole");
        }
        List<byte[]> chainRaw = new ArrayList<>();
        for (Cert c : chain) chainRaw.add(c.raw);
        String did = docId == null ? "" : docId;
        PrepState st = new PrepState(did, cert.raw, chainRaw, attrs, prep.byteRange, pre.revIndex, inHex, hasPage, pageHex, o.claimedRole(),
            pre.priorCmsSha256, prep.pdf, fileName);
        Placement placement = null;
        if (vis != null && prep.placement != null) {
            StampPlacement.Result pl = prep.placement;
            placement = new Placement(vis.page, pl.x / 100.0, pl.y / 100.0, vis.w / 100.0, vis.h / 100.0, PlacementStatus.valueOf(pl.status.name()));
        }
        return new Prepared(Cms.dtbs(attrs), prep.digest, did, st.encode(), placement);
    }

    static Completed complete(byte[] state, byte[] signature, CompleteOptions o, Env env) {
        PrepState st;
        try {
            st = PrepState.decode(state);
        } catch (Exception e) {
            throw new EidPadesException.StateInvalid("state: " + e.getMessage());
        }
        try {
            Structure.check(st.pdf);
        } catch (Structure.Failure e) {
            throw new EidPadesException.StateInvalid("state PDF structure nested too deep or too complex");
        }
        Cert cert;
        try {
            cert = Cert.parse(st.signerCert);
        } catch (Exception e) {
            throw new EidPadesException.StateInvalid("state signerCert");
        }
        List<Cert> chain = new ArrayList<>();
        try {
            for (byte[] d : st.chain) chain.add(Cert.parse(d));
        } catch (Exception e) {
            throw new EidPadesException.StateInvalid("state chain");
        }
        List<Cert> roots = new ArrayList<>();
        try {
            if (o.roots().isEmpty()) roots.add(EidChain.nationalRoot());
            else for (byte[] d : o.roots()) roots.add(Cert.parse(d));
        } catch (Exception e) {
            throw new EidPadesException.RequestInvalid("roots");
        }
        byte[] sig = Cms.citizenSignature(cert, Cms.dtbs(st.signedAttrs), signature);
        if (sig == null) throw new EidPadesException.SignatureInvalid("signature does not verify over the DTBS");
        Fetcher f = new Fetcher(o.transport() != null ? o.transport() : DefaultHttp.INSTANCE);
        Tsa.Token ts;
        try {
            ts = Tsa.timestamp(f, o.tsaUrl() != null ? o.tsaUrl() : DEFAULT_TSA_URL, sig, roots, chain, env.now.get(), env.nonce.get());
        } catch (Exception e) {
            throw new EidPadesException.TsaUnavailable("TSA timestamp: " + e.getMessage());
        }
        byte[] cms;
        try {
            cms = Cms.assemble(st.signedAttrs, cert, chain, sig, ts.raw);
        } catch (Exception e) {
            throw new EidPadesException.SelfValidationFailed("CMS assembly: " + e.getMessage());
        }
        byte[] signed;
        try {
            signed = SignatureRevision.embedCms(st.pdf, st.byteRange, cms);
        } catch (SignatureRevision.PlaceholderOverflow e) {
            throw new EidPadesException.PlaceholderOverflow("CMS does not fit the placeholder: " + e.getMessage());
        } catch (Exception e) {
            throw new EidPadesException.StateInvalid("cannot embed the CMS: " + e.getMessage());
        }
        DssData dss;
        try {
            List<Cert> own = new ArrayList<>();
            own.add(cert);
            own.addAll(chain);
            dss = Ltv.collectWithWait(f, env.now, env.sleep, ts.genTime, roots, own, ts.certificates);
        } catch (CertificateRevoked e) {
            throw new EidPadesException.LtvUnavailable(e.getMessage(), true);
        } catch (Exception e) {
            throw new EidPadesException.LtvUnavailable("OCSP/CRL: " + e.getMessage(), false);
        }
        byte[] out;
        try {
            dss.contents = SignatureRevision.signatureContents(signed, st.byteRange);
            out = Dss.append(signed, dss);
        } catch (Exception e) {
            throw new EidPadesException.SelfValidationFailed("DSS revision: " + e.getMessage());
        }
        if (out.length > MAX_OUTPUT_BYTES) throw new EidPadesException.PdfTooLarge("output larger than 10 MiB");
        // Self-check (Go: CA validator; here light): the new signature is the prepared one, covers its whole revision
        // (`out` extends `signed` unchanged), verifies; signature count = revIndex; /DSS present.
        List<String[]> prior;
        try {
            if (st.byteRange[2] + st.byteRange[3] != signed.length || out.length <= signed.length
                || !java.util.Arrays.equals(java.util.Arrays.copyOf(out, signed.length), signed)) {
                throw new IllegalArgumentException("the signature does not cover its revision");
            }
            prior = Precheck.selfCheck(out, st.byteRange, cms, st.revIndex);
        } catch (Exception e) {
            throw new EidPadesException.SelfValidationFailed("output self-check: " + e.getMessage());
        }
        List<String> priorCms = new ArrayList<>();
        List<String> priorRev = new ArrayList<>();
        for (String[] p : prior) {
            priorCms.add(p[0]);
            priorRev.add(p[1]);
        }
        return new Completed(out, cms, st.docId, Text.hex(Cms.sha256(out)), st.inSha256, st.hasPage, st.pageSha256, cert.raw, st.revIndex,
            Text.hex(Cms.sha256(signed)), priorCms, priorRev, st.fileName, notEmpty(st.claimedRole) ? st.claimedRole : null);
    }

    /** Appearance checks independent of the PDF (Go checkAppearance, APPEARANCE_SPEC.md §1). */
    private static void checkAppearance(SignatureAppearance a, String claimedRole) {
        if (a == null) return;
        for (double v : new double[] {a.x(), a.y(), a.width(), a.height()}) {
            if (!Double.isFinite(v) || v < 0 || v > 14400) throw bad("x, y, width, height must be 0…14400 pt");
        }
        if (a.page() < 0) throw bad("page ≥ 0");
        if (notEmpty(a.lang()) && !a.lang().equals("mn") && !a.lang().equals("en")) throw bad("lang: mn | en");
        String role = claimedRole == null ? "" : claimedRole;
        for (int i = 0; i < role.length(); ) {
            int r = role.codePointAt(i);
            int t = Character.getType(r);
            // Go roleText: no Cc/Cf, valid UTF-8 (a lone surrogate cannot be encoded).
            if (t == Character.CONTROL || t == Character.FORMAT || t == Character.SURROGATE) throw bad("control character in claimedRole");
            i += Character.charCount(r);
        }
    }

    private static EidPadesException bad(String msg) {
        return new EidPadesException.RequestInvalid("appearance: " + msg);
    }

    /**
     * Go resolveDocID (APPEARANCE_SPEC.md §6.6). Unsigned: [given], else random. Signed: (1) the verify-page link; (2) else
     * the earliest-drawn /EIDVerify-marked stamp of a checked e-Seal signature ([Precheck.Result.seals]); a found docId
     * that differs from [given] → REQUEST_INVALID; (3) else [given] (may be empty — visibleSpec rejects a QR then). Never a
     * random docId on a signed document: the CA rejects a rev > 1 registration for an unknown docId (DOC_NOT_FOUND).
     * Returns null for "none".
     */
    private static String resolveDocId(byte[] doc, Precheck.Result pre, String given0) {
        String given = notEmpty(given0) ? given0 : null;
        if (pre.newDoc) return given != null ? given : randomUuid();
        String found = Precheck.docIdFromPage(doc);
        if (found == null) {
            try {
                found = Precheck.docIdFromStamps(doc, pre.seals);
            } catch (Exception e) {
                throw new EidPadesException.PdfInvalid("PDF does not parse (signature stamp): " + e.getMessage());
            }
        }
        if (found != null && given != null && !given.equals(found)) {
            throw new EidPadesException.RequestInvalid("docId does not match the document's verify page / stamp");
        }
        return found != null ? found : given;
    }

    /**
     * Go visibleSpec: page (0 → the last page that is not an eID verify page), h100, language, date (+08), verify URL.
     * [seal] (the signer certificate is an e-Seal one) → the organisation seal stamp (APPEARANCE_SPEC.md §6): with QR when
     * [qr] (§6.5), else without a URL (§6.2). [qr] requires a docId (REQUEST_INVALID).
     */
    private static Appearance.Visible visibleSpec(byte[] doc, PrepareOptions o, String name, Date now, String docId, int revIndex,
                                                  boolean seal, boolean qr) {
        SignatureAppearance a = o.appearance();
        if (docId.isEmpty() && qr) {
            throw new EidPadesException.RequestInvalid("appearance: docId required (document has no verify page or QR stamp)");
        }
        int[] ln;
        try {
            ln = Appearance.defaultStampPage(doc, Precheck.VERIFY_URL + docId);
        } catch (Exception e) {
            throw new EidPadesException.PdfInvalid("not a PDF or damaged: " + e.getMessage());
        }
        int page = a.page() == 0 ? ln[0] : a.page();
        if (page > ln[1]) throw new EidPadesException.RequestInvalid("appearance: page " + page + " > page count " + ln[1]);
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.ROOT);
        df.setTimeZone(TimeZone.getTimeZone("GMT+08:00"));
        String lang = notEmpty(a.lang()) ? a.lang() : notEmpty(o.lang()) ? o.lang() : "mn";
        return new Appearance.Visible(page, Appearance.round100(a.x()), Appearance.round100(a.y()), Appearance.round100(a.width()),
            Appearance.round100(a.height()), Text.trimSpace(name), o.claimedRole() == null ? "" : o.claimedRole(), lang,
            df.format(now) + " (+08)", qr ? Precheck.VERIFY_URL + docId + "/" + revIndex : "", a.exact(), seal);
    }

    /** Go `pades.SuggestPlacement` (PLACEMENT_SPEC.md §6b): [prepare]'s placement without signing. */
    static PlacementSuggestion suggestPlacement(byte[] doc, SignatureAppearance a) {
        checkHeader(doc);
        checkAppearance(a, null);
        String verifyUri = "";
        if (Precheck.hasSignatures(doc)) {
            String id = Precheck.docIdFromPage(doc);
            if (id != null) verifyUri = Precheck.VERIFY_URL + id;
        }
        long w = Appearance.round100(a.width());
        long h = Appearance.round100(a.height());
        Appearance.Suggested s;
        try {
            s = Appearance.suggest(doc, verifyUri, a.page(), Appearance.round100(a.x()), Appearance.round100(a.y()), w, h, a.exact());
        } catch (AppearanceException e) {
            throw new EidPadesException.RequestInvalid("appearance: " + e.getMessage());
        } catch (Exception e) {
            throw new EidPadesException.PdfInvalid("not a PDF or damaged: " + e.getMessage());
        }
        List<PlacementSuggestion.PageSize> pages = new ArrayList<>();
        for (long[] z : s.sizes) pages.add(new PlacementSuggestion.PageSize(z == null ? 0 : z[0] / 100.0, z == null ? 0 : z[1] / 100.0));
        PlacementSuggestion.PageSize cur = pages.get(s.page - 1);
        return new PlacementSuggestion(s.page, s.result.x / 100.0, s.result.y / 100.0, w / 100.0, h / 100.0,
            PlacementStatus.valueOf(s.result.status.name()), cur.width(), cur.height(), pages.size(), pages);
    }

    /** Given chain (DER 04/03/02) or the embedded eID chain followed from the signer's issuer (root excluded). */
    private static List<Cert> signerChain(Cert signer, List<byte[]> ders) {
        if (!ders.isEmpty()) {
            List<Cert> out = new ArrayList<>();
            try {
                for (byte[] d : ders) out.add(Cert.parse(d));
            } catch (Exception e) {
                throw new EidPadesException.SignerInvalid("chain: " + e.getMessage());
            }
            return out;
        }
        List<Cert> pool = EidChain.intermediates();
        List<Cert> chain = new ArrayList<>();
        Cert cur = signer;
        for (int k = 0; k <= pool.size(); k++) {
            Cert next = null;
            for (Cert c : pool) {
                if (cur.issuedBy(c)) {
                    next = c;
                    break;
                }
            }
            if (next == null) continue;
            chain.add(next);
            cur = next;
        }
        if (chain.isEmpty()) throw new EidPadesException.SignerInvalid("signer's issuer is not in the embedded eID chain — pass chain");
        return Collections.unmodifiableList(chain);
    }

    /** CA/Go: drop Cc/Cf/Zl/Zp, NFC, TrimSpace; 1…120 characters. */
    static String cleanFileName(String s) {
        if (s == null) return null;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); ) {
            int r = s.codePointAt(i);
            i += Character.charCount(r);
            int t = Character.getType(r);
            if (t == Character.CONTROL || t == Character.FORMAT || t == Character.LINE_SEPARATOR || t == Character.PARAGRAPH_SEPARATOR
                || t == Character.SURROGATE || r == 0xFFFD) {
                continue;
            }
            sb.appendCodePoint(r);
        }
        String out = Text.trimSpace(Normalizer.normalize(sb, Normalizer.Form.NFC));
        if (out.isEmpty() || out.codePointCount(0, out.length()) > MAX_FILE_NAME) return null;
        return out;
    }

    private static String randomUuid() {
        byte[] b = new byte[16];
        new SecureRandom().nextBytes(b);
        b[6] = (byte) ((b[6] & 0x0f) | 0x40);
        b[8] = (byte) ((b[8] & 0x3f) | 0x80);
        String h = Text.hex(b);
        return h.substring(0, 8) + "-" + h.substring(8, 12) + "-" + h.substring(12, 16) + "-" + h.substring(16, 20) + "-" + h.substring(20);
    }
}
