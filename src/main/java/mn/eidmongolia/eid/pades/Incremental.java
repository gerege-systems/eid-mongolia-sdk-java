package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * One incremental update (revision): output = base + "\n" + new objects + xref + trailer; base bytes never change. 1:1
 * port of the Go reference `pades/internal/core/incremental.go` + `serialize.go` (digitorus fork). New xref streams
 * are written UNCOMPRESSED (no /Filter) — cross-SDK byte identity.
 */
final class Incremental {
    private static final class Entry {
        final int id;
        final int gen;
        final int offset;

        Entry(int id, int gen, int offset) {
            this.id = id;
            this.gen = gen;
            this.offset = offset;
        }
    }

    final PdfReader reader;
    private final ByteArrayOutputStream out;
    private int nextId;
    private final List<Entry> entries = new ArrayList<>();

    Incremental(byte[] base) {
        try {
            reader = PdfReader.open(base);
        } catch (PdfException e) {
            throw e;
        } catch (Exception e) {
            throw new PdfException("PDF: " + e.getMessage());
        }
        if (!reader.get(reader.trailer, "Encrypt").isNull()) throw new PdfException("encrypted PDF");
        if (!(reader.get(reader.trailer, "Root") instanceof PdfObj.Dict)) throw new PdfException("Catalog missing");
        Long size = reader.trailer.get("Size").asLong();
        if (size == null || size <= 0 || size > (1 << 23)) throw new PdfException("bad /Size");
        nextId = Math.max((int) (long) size, reader.maxObjectId() + 1);
        out = new ByteArrayOutputStream(base.length + (64 << 10));
        out.write(base, 0, base.length);
        out.write('\n'); // empty line after %%EOF (digitorus)
    }

    PdfDict root() {
        return ((PdfObj.Dict) reader.get(reader.trailer, "Root")).d();
    }

    PdfRef rootRef() {
        return reader.trailer.get("Root").ref();
    }

    int size() {
        return out.size();
    }

    int reserve() {
        return nextId++;
    }

    private void write(String s) {
        byte[] b = Text.latin1(s);
        out.write(b, 0, b.length);
    }

    int writeObject(int id, byte[] body) {
        return writeObject(id, body, 0);
    }

    /** Writes object `id gen`; returns the offset where its body starts. */
    int writeObject(int id, byte[] body, int gen) {
        out.write('\n');
        entries.add(new Entry(id, gen, out.size()));
        write(id + " " + gen + " obj\n");
        int start = out.size();
        byte[] t = trimSpace(body);
        out.write(t, 0, t.length);
        write("\nendobj\n");
        return start;
    }

    /** Returns the new object's id. */
    int addObject(byte[] body) {
        int id = reserve();
        writeObject(id, body);
        return id;
    }

    /** xref (same kind as the base's latest section) + trailer; [rootId] = the new Catalog. */
    byte[] finish(int rootId) {
        if (entries.isEmpty()) throw new PdfException("no new objects");
        out.write('\n');
        int xrefStart = out.size();
        int xid = 0;
        if (reader.xrefIsStream) {
            xid = reserve();
            entries.add(new Entry(xid, 0, xrefStart));
        }
        entries.sort(Comparator.comparingInt(e -> e.id));
        List<int[]> runs = new ArrayList<>(); // [start index, count]
        for (int i = 0; i < entries.size(); i++) {
            Entry e = entries.get(i);
            if (i > 0 && e.id == entries.get(i - 1).id) throw new PdfException("duplicate object number");
            if (i > 0 && e.id == entries.get(i - 1).id + 1) {
                runs.get(runs.size() - 1)[1]++;
                continue;
            }
            runs.add(new int[] {i, 1});
        }
        int prev = reader.startXref;
        StringBuilder extra = new StringBuilder();
        PdfDict tr = reader.trailer;
        PdfObj infoRaw = tr.get("Info");
        PdfObj info = reader.resolve(infoRaw);
        if (!info.isNull()) {
            PdfRef r = infoRaw.ref();
            if (r == null) extra.append(" /Info ").append(serialize(info)); // direct /Info (profile pades-client/1, P3)
            else extra.append(" /Info ").append(r.id()).append(' ').append(r.gen()).append(" R");
        }
        PdfObj id = reader.resolve(tr.get("ID"));
        if (id instanceof PdfObj.Arr && ((PdfObj.Arr) id).items().size() == 2) {
            List<PdfObj> items = ((PdfObj.Arr) id).items();
            PdfObj a0 = reader.resolve(items.get(0));
            PdfObj b0 = reader.resolve(items.get(1));
            byte[] a = a0 instanceof PdfObj.Str ? ((PdfObj.Str) a0).bytes() : new byte[0];
            byte[] b = b0 instanceof PdfObj.Str ? ((PdfObj.Str) b0).bytes() : new byte[0];
            extra.append(" /ID [").append(Text.hexString(a)).append(' ').append(Text.hexString(b)).append(']');
        }
        if (!reader.xrefIsStream) {
            StringBuilder sb = new StringBuilder("xref\n");
            for (int[] r : runs) {
                sb.append(entries.get(r[0]).id).append(' ').append(r[1]).append('\n');
                for (int k = r[0]; k < r[0] + r[1]; k++) {
                    Entry e = entries.get(k);
                    sb.append(String.format(Locale.ROOT, "%010d %05d n\r\n", e.offset, e.gen));
                }
            }
            sb.append("trailer\n<< /Size ").append(nextId).append(" /Root ").append(rootId).append(" 0 R").append(extra)
                .append(" /Prev ").append(prev).append(" >>\nstartxref\n").append(xrefStart).append("\n%%EOF\n");
            write(sb.toString());
            return out.toByteArray();
        }
        ByteArrayOutputStream rows = new ByteArrayOutputStream(entries.size() * 6);
        for (Entry e : entries) {
            if (e.gen > 0xff) throw new PdfException("generation does not fit 1 byte");
            rows.write(1);
            rows.write(e.offset >>> 24);
            rows.write((e.offset >> 16) & 0xff);
            rows.write((e.offset >> 8) & 0xff);
            rows.write(e.offset & 0xff);
            rows.write(e.gen);
        }
        StringBuilder index = new StringBuilder();
        for (int[] r : runs) {
            if (index.length() > 0) index.append(' ');
            index.append(entries.get(r[0]).id).append(' ').append(r[1]);
        }
        write(xid + " 0 obj\n<< /Type /XRef /Length " + rows.size() + " /W [1 4 1] /Prev " + prev + " /Size " + nextId
            + " /Index [" + index + "] /Root " + rootId + " 0 R" + extra + " >>\nstream\n");
        byte[] rb = rows.toByteArray();
        out.write(rb, 0, rb.length);
        write("\nendstream\nendobj\nstartxref\n" + xrefStart + "\n%%EOF\n");
        return out.toByteArray();
    }

    /** Catalog keys except /Type and [skip], as "  /Key value\n" (digitorus createCatalog). */
    String catalogCopy(Set<String> skip) {
        StringBuilder sb = new StringBuilder();
        PdfDict r = root();
        for (String key : r.sortedKeys()) {
            if (key.equals("Type") || skip.contains(key)) continue;
            sb.append("  /").append(escapeName(key)).append(' ').append(serialize(r.get(key))).append('\n');
        }
        return sb.toString();
    }

    String serialize(PdfObj v) {
        return serialize(v, 0);
    }

    /**
     * Go serialize.go: direct values are rewritten; references stay "N G R" (a reference to a missing object → "null").
     * Strings as hex, names #xx-escaped, reals without exponent.
     */
    String serialize(PdfObj v, int depth) {
        if (depth > 32) throw new PdfException("value nested too deep");
        if (v instanceof PdfObj.Null) return "null";
        if (v instanceof PdfObj.Ref) {
            PdfRef r = ((PdfObj.Ref) v).r();
            return reader.obj(r).isNull() ? "null" : r.id() + " " + r.gen() + " R";
        }
        if (v instanceof PdfObj.Str) return Text.hexString(((PdfObj.Str) v).bytes());
        if (v instanceof PdfObj.Bool) return ((PdfObj.Bool) v).v() ? "true" : "false";
        if (v instanceof PdfObj.Int) return Long.toString(((PdfObj.Int) v).v());
        if (v instanceof PdfObj.Real) return formatReal(((PdfObj.Real) v).v());
        if (v instanceof PdfObj.Name) return "/" + escapeName(((PdfObj.Name) v).v());
        if (v instanceof PdfObj.Dict) {
            PdfDict d = ((PdfObj.Dict) v).d();
            StringBuilder sb = new StringBuilder("<<");
            for (String key : d.sortedKeys()) sb.append(" /").append(escapeName(key)).append(' ').append(serialize(d.get(key), depth + 1));
            return sb.append(" >>").toString();
        }
        if (v instanceof PdfObj.Arr) {
            StringBuilder sb = new StringBuilder("[");
            List<PdfObj> items = ((PdfObj.Arr) v).items();
            for (int i = 0; i < items.size(); i++) {
                if (i > 0) sb.append(' ');
                sb.append(serialize(items.get(i), depth + 1));
            }
            return sb.append(']').toString();
        }
        throw new PdfException("cannot copy a direct stream");
    }

    static String escapeName(String n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n.length(); i++) {
            char ch = n.charAt(i);
            int c = ch & 0xff;
            if (c < 0x21 || c > 0x7e || "#()<>[]{}/%".indexOf(ch) >= 0) sb.append(String.format(Locale.ROOT, "#%02X", c));
            else sb.append(ch);
        }
        return sb.toString();
    }

    /** Go strconv.FormatFloat(f, 'f', -1, 64): shortest round-trip digits, never an exponent. */
    static String formatReal(double d) {
        if (d == Math.rint(d) && Math.abs(d) < 1e15) return Long.toString((long) d);
        return new BigDecimal(Double.toString(d)).stripTrailingZeros().toPlainString();
    }

    /** Go bytes.TrimSpace (ASCII whitespace). */
    static byte[] trimSpace(byte[] b) {
        int lo = 0;
        int hi = b.length;
        while (lo < hi && ws(b[lo])) lo++;
        while (hi > lo && ws(b[hi - 1])) hi--;
        return lo == 0 && hi == b.length ? b : java.util.Arrays.copyOfRange(b, lo, hi);
    }

    private static boolean ws(byte c) {
        return c == 9 || c == 10 || c == 11 || c == 12 || c == 13 || c == 32;
    }
}
