package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * /DSS revision (R_dss) — Go reference `pades/internal/core/dss.go`. Keeps every old DSS entry, reuses byte-identical
 * old streams by reference, writes new streams UNCOMPRESSED, VRI key = SHA1(/Contents) upper hex.
 */
final class Dss {
    private static final int MAX_DSS_STREAM = 4 << 20;
    private static final String[] KEYS = {"Certs", "OCSPs", "CRLs"};

    private Dss() {
    }

    static byte[] append(byte[] signed, DssData d) {
        if (d.certs.size() + d.ocsps.size() + d.crls.size() == 0) throw new IllegalArgumentException("DSS empty");
        Incremental inc = new Incremental(signed);
        PdfReader rd = inc.reader;
        PdfDict root = inc.root();
        PdfObj oldObj = rd.get(root, "DSS");
        if (!oldObj.isNull() && !(oldObj instanceof PdfObj.Dict)) throw new PdfException("/DSS is not a dictionary");
        PdfDict old = oldObj instanceof PdfObj.Dict ? ((PdfObj.Dict) oldObj).d() : null;
        Map<String, String> known = new HashMap<>(); // sha256 hex of stream data → reference
        Map<String, List<String>> lists = new HashMap<>();
        for (String key : KEYS) {
            if (old == null) continue;
            PdfObj a = rd.get(old, key);
            if (!(a instanceof PdfObj.Arr)) continue;
            for (PdfObj e : ((PdfObj.Arr) a).items()) {
                String ref = inc.serialize(e);
                lists.computeIfAbsent(key, k -> new ArrayList<>()).add(ref);
                PdfObj v;
                try {
                    v = rd.resolve(e);
                } catch (Exception x) {
                    v = null;
                }
                if (v instanceof PdfObj.Stream) {
                    try {
                        byte[] data = rd.decodedStream(v);
                        if (data.length > MAX_DSS_STREAM) data = Arrays.copyOf(data, MAX_DSS_STREAM);
                        known.put(Text.hex(Cms.sha256(data)), ref);
                    } catch (Exception x) {
                        // not reusable
                    }
                }
            }
        }
        List<List<String>> vriEntry = List.of(new ArrayList<String>(), new ArrayList<String>(), new ArrayList<String>());
        List<List<byte[]>> items = List.of(d.certs, d.ocsps, d.crls);
        for (int slot = 0; slot < 3; slot++) {
            String key = KEYS[slot];
            for (byte[] der : items.get(slot)) {
                String sum = Text.hex(Cms.sha256(der));
                String ref = known.get(sum);
                if (ref == null) {
                    byte[] s = Der.concat(Text.latin1("<< /Length " + der.length + " >>\nstream\n"), der, Text.latin1("\nendstream"));
                    int id = inc.addObject(s);
                    ref = id + " 0 R";
                    known.put(sum, ref);
                    lists.computeIfAbsent(key, k -> new ArrayList<>()).add(ref);
                }
                if (!vriEntry.get(slot).contains(ref)) vriEntry.get(slot).add(ref);
            }
        }

        StringBuilder dss = new StringBuilder("<<");
        for (String key : KEYS) {
            List<String> l = lists.get(key);
            if (l != null && !l.isEmpty()) dss.append(" /").append(key).append(" [").append(String.join(" ", l)).append(']');
        }
        PdfObj vri = old == null ? null : rd.get(old, "VRI");
        byte[] contents = d.contents;
        boolean hasContents = contents != null && contents.length > 0;
        if (hasContents || vri instanceof PdfObj.Dict) {
            dss.append(" /VRI <<");
            String newKey = hasContents ? Text.hex(Cms.sha1(contents)).toUpperCase(Locale.ROOT) : null;
            if (vri instanceof PdfObj.Dict) {
                PdfDict vd = ((PdfObj.Dict) vri).d();
                for (String key : vd.sortedKeys()) {
                    if (key.equals(newKey)) continue;
                    dss.append(" /").append(Incremental.escapeName(key)).append(' ').append(inc.serialize(vd.get(key)));
                }
            }
            if (newKey != null) {
                dss.append(" /").append(newKey).append(" <<");
                String[] names = {"Cert", "OCSP", "CRL"};
                for (int i = 0; i < 3; i++) {
                    if (!vriEntry.get(i).isEmpty()) dss.append(" /").append(names[i]).append(" [").append(String.join(" ", vriEntry.get(i))).append(']');
                }
                dss.append(" >>");
            }
            dss.append(" >>");
        }
        dss.append(" >>");
        int dssId = inc.addObject(Text.latin1(dss.toString()));
        StringBuilder cat = new StringBuilder("<<\n  /Type /Catalog\n");
        cat.append(inc.catalogCopy(Set.of("DSS")));
        cat.append("  /DSS ").append(dssId).append(" 0 R\n>>");
        int catId = inc.addObject(Text.latin1(cat.toString()));
        return inc.finish(catId);
    }
}
