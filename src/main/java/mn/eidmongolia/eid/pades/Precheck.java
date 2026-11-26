package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;

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
        /** Checked e-Seal signatures: signature dictionary object number → position (APPEARANCE_SPEC.md §6.6). */
        final Map<Integer, Integer> seals;

        Result(boolean newDoc, int revIndex, List<String> priorCmsSha256, Map<Integer, Integer> seals) {
            this.newDoc = newDoc;
            this.revIndex = revIndex;
            this.priorCmsSha256 = priorCmsSha256;
            this.seals = seals;
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
        if (sigs.isEmpty()) return new Result(true, 1, Collections.emptyList(), Collections.emptyMap());
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
        return new Result(false, sigs.size() + 1, prior, stampSources(sigs, checked));
    }

    /**
     * Go stampSources (APPEARANCE_SPEC.md §6.6 step 2.2): of the checked signatures ONLY those with an e-Seal certificate,
     * signature dictionary object number → position (1 + the number of checked signatures whose ByteRange[2] + [3] is
     * smaller — PRECHECKS #6 / the validator's revIndex). A citizen signature is never a docId source.
     */
    private static Map<Integer, Integer> stampSources(List<SigDict> sigs, List<Checked> checked) {
        Map<Integer, Integer> out = new HashMap<>();
        for (int i = 0; i < sigs.size(); i++) {
            if (!mn.eidmongolia.eid.SealService.isSealCertificate(checked.get(i).leaf.raw)) continue;
            SigDict s = sigs.get(i);
            long end = s.byteRange.get(2) + s.byteRange.get(3);
            int rev = 1;
            for (SigDict o : sigs) {
                if (o.byteRange.get(2) + o.byteRange.get(3) < end) rev++;
            }
            out.put(s.obj, rev);
        }
        return out;
    }

    /** The QR stamp form stream's first line (APPEARANCE_SPEC.md §5 step 6): docId = group 1, rev = group 2. */
    private static final Pattern STAMP_MARKER = Pattern.compile(
        "^/EIDVerify <</URL \\(https://ca\\.eidmongolia\\.mn/verify/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/([1-9][0-9]?)\\)>> BDC\n");
    /** The marker line's maximum length read from the form stream (bytes). */
    private static final int STAMP_MARKER_MAX = 128;

    /**
     * Go docIDFromStamps (APPEARANCE_SPEC.md §6.6 step 2.2): the docId of the earliest-drawn /EIDVerify-marked stamp of the
     * checked e-Seal signatures [seals]. Widget = a dictionary object of the latest xref with its OWN {@code /FT /Sig} and
     * its OWN {@code /V} an indirect reference (raw, not resolved; number and generation as in the xref) to one of [seals].
     * Two passes: (1) count each seal signature's widgets (+ the first, in object order), skipping objects that do not
     * read; (2) read the stamp only of a signature with exactly ONE widget: {@code /AP} dict, {@code /N} stream,
     * {@code /Filter} absent or a DIRECT null, the first ≤ 128 of the stream's {@code /Length} bytes match [STAMP_MARKER]
     * and the marker's rev equals that signature's position. Smallest ByteRange[2] + [3] wins (tie: smaller object
     * number). None → null. A read failure of a single-widget candidate's own /AP, /N, /Length, /DecodeParms or stream
     * throws (Prepare: PDF_INVALID) whatever the xref order. A hint for choosing the docId, not a proof — Complete's
     * checks and the validators decide.
     */
    static String docIdFromStamps(byte[] doc, Map<Integer, Integer> seals) {
        if (seals.isEmpty()) return null;
        PdfReader r = PdfReader.open(doc);
        Map<Integer, Integer> widgets = new HashMap<>();
        Map<Integer, Integer> first = new HashMap<>();
        for (int id : r.objectIds()) {
            PdfDict d;
            try {
                PdfObj v = strictObj(r, new PdfRef(id, xrefGen(r, id)));
                if (!(v instanceof PdfObj.Dict)) continue;
                d = ((PdfObj.Dict) v).d();
            } catch (RuntimeException e) {
                continue;
            }
            PdfRef sp = d.get("V").ref();
            if (sp == null || !seals.containsKey(sp.id()) || !r.xref.containsKey(sp.id()) || xrefGen(r, sp.id()) != sp.gen()) continue;
            String ft;
            try {
                ft = strict(r, d.get("FT")).name();
            } catch (RuntimeException e) {
                continue;
            }
            if (!"Sig".equals(ft)) continue;
            int n = widgets.merge(sp.id(), 1, Integer::sum);
            if (n == 1) first.put(sp.id(), id);
        }
        long best = Long.MAX_VALUE;
        int bestObj = 0;
        String found = null;
        for (Map.Entry<Integer, Integer> e : widgets.entrySet()) {
            if (e.getValue() != 1) continue;
            int obj = e.getKey();
            Object[] st = readStamp(r, first.get(obj), obj, seals.get(obj));
            String id = (String) st[0];
            long end = (Long) st[1];
            if (id == null || end < 0) continue;
            if (end < best || end == best && obj < bestObj) {
                best = end;
                bestObj = obj;
                found = id;
            }
        }
        return found;
    }

    private static int xrefGen(PdfReader r, int id) {
        PdfReader.XrefEntry xe = r.xref.get(id);
        return xe == null || xe.compressed ? 0 : xe.gen;
    }

    /**
     * [PdfReader.obj] with the Go pdf reader's check that the object found at the xref offset carries the referenced
     * number AND generation ("n g obj"; Go panics on a mismatch) — this step's reads follow the Go reader exactly.
     */
    private static PdfObj strictObj(PdfReader r, PdfRef ref) {
        PdfReader.XrefEntry xe = r.xref.get(ref.id());
        if (xe != null && !xe.compressed && xe.gen == ref.gen()) {
            PdfLexer lx = new PdfLexer(r.bytes, xe.off);
            Integer n = PdfLexer.toInt(lx.word());
            Integer g = PdfLexer.toInt(lx.word());
            if (n == null || g == null || n != ref.id() || g != ref.gen()) throw new PdfException("object " + ref.id() + " not at its xref offset");
        }
        return r.obj(ref);
    }

    /** [PdfReader.resolve] through [strictObj]. */
    private static PdfObj strict(PdfReader r, PdfObj o) {
        PdfObj cur = o;
        int n = 0;
        while (cur instanceof PdfObj.Ref) {
            if (++n >= 16) throw new PdfException("reference loop");
            cur = strictObj(r, ((PdfObj.Ref) cur).r());
        }
        return cur;
    }

    /** Go readStamp: {docId or null, ByteRange[2] + [3] or -1} of a single-widget e-Seal signature. Read errors throw. */
    private static Object[] readStamp(PdfReader r, int widget, int sig, int rev) {
        PdfDict w = strictObj(r, new PdfRef(widget, xrefGen(r, widget))).dict();
        PdfDict s = strictObj(r, new PdfRef(sig, xrefGen(r, sig))).dict();
        long end = -1;
        PdfObj br = s == null ? PdfObj.NULL : strict(r, s.get("ByteRange"));
        if (br instanceof PdfObj.Arr && ((PdfObj.Arr) br).items().size() == 4) {
            PdfObj b2 = strict(r, ((PdfObj.Arr) br).items().get(2));
            PdfObj b3 = strict(r, ((PdfObj.Arr) br).items().get(3));
            if (b2 instanceof PdfObj.Int && b3 instanceof PdfObj.Int) end = ((PdfObj.Int) b2).v() + ((PdfObj.Int) b3).v();
        }
        PdfObj ap = w == null ? PdfObj.NULL : strict(r, w.get("AP"));
        PdfObj n = ap instanceof PdfObj.Dict ? strict(r, ((PdfObj.Dict) ap).d().get("N")) : PdfObj.NULL;
        if (!(n instanceof PdfObj.Stream)) return new Object[] {null, end};
        PdfObj.Stream ns = (PdfObj.Stream) n;
        // /Filter: absent or a DIRECT null only (an indirect one, even to null, is not "absent" — §6.3).
        if (!(ns.d().get("Filter") instanceof PdfObj.Null)) return new Object[] {null, end};
        // Go Value.Reader: /Length (resolved; non-integer → 0) bytes from the stream start; /DecodeParms is resolved too.
        PdfObj len = strict(r, ns.d().get("Length"));
        strict(r, ns.d().get("DecodeParms"));
        long length = len instanceof PdfObj.Int ? ((PdfObj.Int) len).v() : 0;
        int start = ns.start();
        // Go's lexer requires an EOL after `stream` (else it fails → PDF_INVALID).
        if (start < 1 || r.bytes[start - 1] != '\n' && r.bytes[start - 1] != '\r') throw new PdfException("stream keyword not followed by newline");
        int stop = (int) Math.min((long) start + Math.max(0, Math.min(length, STAMP_MARKER_MAX)), r.bytes.length);
        String head = new String(r.bytes, start, Math.max(0, stop - start), StandardCharsets.ISO_8859_1);
        java.util.regex.Matcher m = STAMP_MARKER.matcher(head);
        if (m.find() && m.group(2).equals(Integer.toString(rev))) return new Object[] {m.group(1), end};
        return new Object[] {null, end};
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
