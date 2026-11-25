package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

/** Embedded eID chain (same PEMs as Go `pades/internal/eidcrypto/chain`). Immutable, loaded once. */
final class EidChain {
    private EidChain() {
    }

    static byte[] resource(String path) {
        try (InputStream s = EidChain.class.getResourceAsStream("/mn/eidmongolia/eid/pades/" + path)) {
            if (s == null) throw new IllegalStateException("resource " + path + " missing");
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException("resource " + path, e);
        }
    }

    private static Cert load(String name) {
        return Cert.parse(Cert.pemSingle(resource("chain/" + name)));
    }

    private static final class Holder {
        static final Cert ROOT = load("01-mongolian-national-root-ca.pem");
        static final List<Cert> INTERMEDIATES = Collections.unmodifiableList(Arrays.asList(
            load("02-mongolian-national-issuing-ca-mddc.pem"), load("03-gerege-issuing-ca.pem"),
            load("04-eid-mongolia-issuing-ca.pem"), load("05-eid-mongolia-org-issuing-ca.pem")));
    }

    static Cert nationalRoot() {
        return Holder.ROOT;
    }

    static List<Cert> intermediates() {
        return Holder.INTERMEDIATES;
    }

    /** eID issuing CAs (04 natural persons, 05 organisations). */
    static List<Cert> issuers() {
        return Holder.INTERMEDIATES.subList(2, 4);
    }
}

/**
 * Light prepare checks — exactly `pades/PRECHECKS.md` of the Go reference (no revision validator in native SDKs).
 * Steps 1–3 (size, `%PDF-`, signer cert) run in [Pades.prepare]; this covers 4–10.
 */
final class Precheck {
    static final int MAX_SIGNATURES = 16;
    static final String VERIFY_URL = "https://ca.eidmongolia.mn/verify/";
    static final Pattern UUID_RE = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");

    private Precheck() {
    }

    static final class Result {
        final boolean newDoc;
        final int revIndex;
        final List<String> priorCmsSha256;

        Result(boolean newDoc, int revIndex, List<String> priorCmsSha256) {
            this.newDoc = newDoc;
            this.revIndex = revIndex;
            this.priorCmsSha256 = priorCmsSha256;
        }
    }

    private static final class SigDict {
        final int obj;
        final List<Long> byteRange;
        final String subFilter;
        final String type;

        SigDict(int obj, List<Long> byteRange, String subFilter, String type) {
            this.obj = obj;
            this.byteRange = byteRange;
            this.subFilter = subFilter;
            this.type = type;
        }
    }

    private static final class Scanned {
        final List<SigDict> sigs;
        final boolean locked;
        final boolean hasDss;

        Scanned(List<SigDict> sigs, boolean locked, boolean hasDss) {
            this.sigs = sigs;
            this.locked = locked;
            this.hasDss = hasDss;
        }
    }

    private static final class Checked {
        final Cert leaf;
        final boolean stamped;
        final String cmsSha256;

        Checked(Cert leaf, boolean stamped, String cmsSha256) {
            this.leaf = leaf;
            this.stamped = stamped;
            this.cmsSha256 = cmsSha256;
        }
    }

    static Result run(byte[] doc, List<Cert> issuers) {
        Scanned sc = open(doc);
        List<SigDict> sigs = sc.sigs;
        if (sigs.isEmpty()) return new Result(true, 1, Collections.emptyList());
        if (sigs.size() >= MAX_SIGNATURES) throw new EidPadesException.PdfTooManySignatures("too many signatures");
        List<Checked> checked = new ArrayList<>();
        for (SigDict s : sigs) {
            try {
                checked.add(checkPriorSignature(doc, s));
            } catch (Exception e) {
                throw new EidPadesException.PdfPriorSignatureInvalid("prior signature invalid: " + e.getMessage());
            }
        }
        if (sc.locked) throw new EidPadesException.PdfLocked("document is certified with DocMDP P=1");
        List<String> prior = new ArrayList<>();
        for (int i = 0; i < sigs.size(); i++) {
            SigDict s = sigs.get(i);
            Checked c = checked.get(i);
            boolean byEid = false;
            for (Cert iss : issuers) byEid |= c.leaf.issuedBy(iss);
            if (!SignatureRevision.SUB_FILTER.equals(s.subFilter) || !byEid || !c.stamped || !sc.hasDss) {
                throw new EidPadesException.PdfForeignSignature("document has a non-eID signature");
            }
            prior.add(c.cmsSha256);
        }
        return new Result(false, sigs.size() + 1, prior);
    }

    /**
     * Light self-check of `complete`'s output: the document parses, its signature count is [revIndex], the final Catalog
     * has /DSS, and the signature whose ByteRange is [own] has exactly [cms] as /Contents and passes step 8. Returns the
     * prior signatures' {CMS sha256, revision sha256}, object order.
     */
    static List<String[]> selfCheck(byte[] out, long[] own, byte[] cms, int revIndex) {
        Scanned sc = scan(out);
        if (!sc.hasDss) throw new IllegalArgumentException("no /DSS");
        List<Long> ownList = Arrays.asList(own[0], own[1], own[2], own[3]);
        String cmsHex = Text.hex(Cms.sha256(cms));
        boolean found = false;
        int count = 0;
        List<String[]> prior = new ArrayList<>();
        for (SigDict s : sc.sigs) {
            if (s.type != null && !s.type.equals("Sig")) continue;
            count++;
            Checked c = checkPriorSignature(out, s);
            if (ownList.equals(s.byteRange)) {
                if (found || !c.cmsSha256.equals(cmsHex)) throw new IllegalArgumentException("the new signature is not the prepared one");
                found = true;
            } else {
                List<Long> br = s.byteRange;
                MessageDigest h = Cms.md("SHA-256");
                h.update(out, 0, (int) (br.get(2) + br.get(3)));
                prior.add(new String[] {c.cmsSha256, Text.hex(h.digest())});
            }
        }
        if (!found || count != revIndex) throw new IllegalArgumentException("signature count " + count + ", want " + revIndex);
        return prior;
    }

    /** PRECHECKS #4–#6 (Go `encrypted` + `scanSignatures`): encryption, then the signature dicts. */
    private static Scanned open(byte[] doc) {
        if (encrypted(doc)) throw new EidPadesException.PdfEncrypted("encrypted PDF is not supported");
        try {
            return scan(doc);
        } catch (EidPadesException e) {
            throw e;
        } catch (Exception e) {
            throw new EidPadesException.PdfInvalid("not a PDF or damaged: " + e.getMessage());
        }
    }

    /** [Pades.suggestPlacement]: PRECHECKS #4–#6 as in [run]; true when the document has signature dicts. */
    static boolean hasSignatures(byte[] doc) {
        return !open(doc).sigs.isEmpty();
    }

    private static boolean encrypted(byte[] doc) {
        try {
            PdfReader r = PdfReader.open(doc);
            return !r.trailer.get("Encrypt").isNull();
        } catch (Exception e) {
            return Structure.hasEncryptRef(doc);
        }
    }

    /** Signature dicts (object order) + DocMDP P=1 lock + final Catalog has a /DSS dict. */
    private static Scanned scan(byte[] doc) {
        PdfReader r = PdfReader.open(doc);
        PdfObj root = r.get(r.trailer, "Root");
        if (!(root instanceof PdfObj.Dict)) throw new PdfException("Catalog missing");
        PdfDict rd = ((PdfObj.Dict) root).d();
        boolean locked = false;
        boolean hasDss = r.get(rd, "DSS") instanceof PdfObj.Dict;
        PdfDict perms = r.get(rd, "Perms").dict();
        if (perms != null) {
            PdfDict mdp = r.get(perms, "DocMDP").dict();
            if (mdp != null && docMdpP1(r, mdp)) locked = true;
        }
        List<SigDict> sigs = new ArrayList<>();
        for (int id : r.objectIds()) {
            PdfReader.XrefEntry xe = r.xref.get(id);
            int gen = xe.compressed ? 0 : xe.gen;
            PdfObj v = r.obj(new PdfRef(id, gen));
            if (!(v instanceof PdfObj.Dict)) continue;
            PdfDict d = ((PdfObj.Dict) v).d();
            if (r.get(d, "ByteRange").isNull() || r.get(d, "Contents").isNull()) continue;
            List<Long> br = null;
            PdfObj bra = r.get(d, "ByteRange");
            if (bra instanceof PdfObj.Arr) {
                br = new ArrayList<>();
                for (PdfObj it : ((PdfObj.Arr) bra).items()) {
                    PdfObj x = r.resolve(it);
                    if (!(x instanceof PdfObj.Int)) {
                        br = null;
                        break;
                    }
                    br.add(((PdfObj.Int) x).v());
                }
            }
            if (docMdpP1(r, d)) locked = true;
            sigs.add(new SigDict(id, br, r.get(d, "SubFilter").name(), r.get(d, "Type").name()));
        }
        sigs.sort((a, b) -> Integer.compare(a.obj, b.obj));
        return new Scanned(sigs, locked, hasDss);
    }

    /** /Reference row with /TransformMethod /DocMDP (or none) and /TransformParams /P 1. */
    private static boolean docMdpP1(PdfReader r, PdfDict sig) {
        PdfObj ref = r.get(sig, "Reference");
        if (!(ref instanceof PdfObj.Arr)) return false;
        for (PdfObj e : ((PdfObj.Arr) ref).items()) {
            PdfDict d = r.resolve(e).dict();
            if (d == null) continue;
            PdfObj m = r.get(d, "TransformMethod");
            PdfDict tp = r.get(d, "TransformParams").dict();
            PdfObj p = tp == null ? null : r.get(tp, "P");
            if ((m.isNull() || "DocMDP".equals(m.name())) && p instanceof PdfObj.Int && ((PdfObj.Int) p).v() == 1L) return true;
        }
        return false;
    }

    /** Step 8: structural ByteRange checks + CMS signature over the ByteRange bytes (no chain/revocation/time). */
    private static Checked checkPriorSignature(byte[] doc, SigDict s) {
        List<Long> br = s.byteRange;
        if (br == null || br.size() != 4 || br.get(0) != 0L || br.get(1) <= 0 || br.get(2) > doc.length || br.get(3) > doc.length
            || br.get(2) <= br.get(1) + 1 || br.get(3) < 0 || br.get(2) + br.get(3) > doc.length) {
            throw new IllegalArgumentException("ByteRange");
        }
        int a = (int) (long) br.get(1);
        int b = (int) (long) br.get(2);
        if (doc[a] != '<' || doc[b - 1] != '>') throw new IllegalArgumentException("ByteRange does not point at /Contents");
        // The signature covers its revision up to %%EOF (trailing CR/LF trimmed).
        int end = (int) (br.get(2) + br.get(3));
        while (end > 0 && (doc[end - 1] == '\r' || doc[end - 1] == '\n')) end--;
        if (end < 5 || !new String(doc, end - 5, 5, StandardCharsets.ISO_8859_1).equals("%%EOF")) {
            throw new IllegalArgumentException("ByteRange does not end at %%EOF");
        }
        byte[] raw = Text.unhex(doc, a + 1, b - 1);
        if (raw == null) throw new IllegalArgumentException("/Contents hex");
        Der.Tlv first = Der.parse(raw);
        if (first.tag != Der.SEQUENCE) throw new IllegalArgumentException("CMS is not DER");
        byte[] der = first.encoded();
        Cms.Parsed p = Cms.parse(der);
        if (p.signerCount != 1 || p.signer == null) throw new IllegalArgumentException("CMS signer");
        int tail = (int) (long) br.get(3);
        byte[] signed = new byte[a + tail];
        System.arraycopy(doc, 0, signed, 0, a);
        System.arraycopy(doc, b, signed, a, tail);
        if (!Cms.verify(p, signed)) throw new IllegalArgumentException("signature");
        return new Checked(p.signer, p.unsignedAttrOids.contains(Cms.OID_TIMESTAMP_TOKEN), Text.hex(Cms.sha256(der)));
    }

    /** docId from the first eID verify-page link (`/Subtype /Link`, `/A /URI` = VERIFY_URL + lowercase UUID). */
    static String docIdFromPage(byte[] doc) {
        try {
            PdfReader r = PdfReader.open(doc);
            for (int id : r.objectIds()) {
                PdfReader.XrefEntry xe = r.xref.get(id);
                int gen = xe.compressed ? 0 : xe.gen;
                PdfObj o = r.obj(new PdfRef(id, gen));
                if (!(o instanceof PdfObj.Dict)) continue;
                PdfDict v = ((PdfObj.Dict) o).d();
                if (!"Link".equals(r.get(v, "Subtype").name())) continue;
                PdfDict a = r.get(v, "A").dict();
                if (a == null) continue;
                PdfObj uri = r.get(a, "URI");
                if (!(uri instanceof PdfObj.Str)) continue;
                String u = new String(((PdfObj.Str) uri).bytes(), StandardCharsets.ISO_8859_1);
                if (u.startsWith(VERIFY_URL) && UUID_RE.matcher(u.substring(VERIFY_URL.length())).matches()) {
                    return u.substring(VERIFY_URL.length());
                }
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }
}
