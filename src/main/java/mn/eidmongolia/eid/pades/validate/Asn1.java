package mn.eidmongolia.eid.pades.validate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Minimal DER reader — 1:1 with TS src/pades/asn1.ts (readNode / children / expect / oidString / intValue / times). */
final class Asn1 {
    static final int BOOLEAN = 0x01;
    static final int INTEGER = 0x02;
    static final int BIT_STRING = 0x03;
    static final int OCTET_STRING = 0x04;
    static final int OID = 0x06;
    static final int ENUMERATED = 0x0a;
    static final int UTF8 = 0x0c;
    static final int PRINTABLE = 0x13;
    static final int IA5 = 0x16;
    static final int UTC_TIME = 0x17;
    static final int GENERALIZED_TIME = 0x18;
    static final int SEQUENCE = 0x30;
    static final int SET = 0x31;

    /** Go time.Time zero value (0001-01-01T00:00:00Z). */
    static final Instant ZERO = Instant.parse("0001-01-01T00:00:00Z");

    private Asn1() {
    }

    static final class Error extends RuntimeException {
        Error(String m) {
            super(m);
        }
    }

    /** One TLV over [buf]: raw = [start, end), value = [vs, end). */
    static final class Node {
        final byte[] buf;
        final int tag;
        final int start;
        final int vs;
        final int end;

        Node(byte[] buf, int tag, int start, int vs, int end) {
            this.buf = buf;
            this.tag = tag;
            this.start = start;
            this.vs = vs;
            this.end = end;
        }

        byte[] raw() {
            return Arrays.copyOfRange(buf, start, end);
        }

        byte[] value() {
            return Arrays.copyOfRange(buf, vs, end);
        }

        int rawLength() {
            return end - start;
        }

        int length() {
            return end - vs;
        }
    }

    static Node readNode(byte[] b, int off) {
        return readNode(b, off, b.length);
    }

    /** One TLV of b[off:lim] (DER definite length, single-byte tag). */
    static Node readNode(byte[] b, int off, int lim) {
        if (off + 2 > lim) throw new Error("asn1: truncated");
        int tag = b[off] & 0xff;
        if ((tag & 0x1f) == 0x1f) throw new Error("asn1: multi-byte tag");
        long len = b[off + 1] & 0xff;
        int p = off + 2;
        if ((len & 0x80) != 0) {
            int n = (int) (len & 0x7f);
            if (n == 0 || n > 4) throw new Error("asn1: bad length");
            if (p + n > lim) throw new Error("asn1: truncated");
            if (b[p] == 0) throw new Error("asn1: non-minimal length");
            len = 0;
            for (int i = 0; i < n; i++) len = len * 256 + (b[p + i] & 0xff);
            if (len < 0x80) throw new Error("asn1: non-minimal length");
            p += n;
        }
        if (p + len > lim) throw new Error("asn1: truncated");
        return new Node(b, tag, off, p, (int) (p + len));
    }

    /** A single TLV with nothing after it. */
    static Node parseOne(byte[] b) {
        Node n = readNode(b, 0);
        if (n.end != b.length) throw new Error("asn1: trailing data");
        return n;
    }

    static List<Node> children(Node n) {
        List<Node> out = new ArrayList<>();
        for (int p = n.vs; p < n.end; ) {
            Node c = readNode(n.buf, p, n.end);
            out.add(c);
            p = c.end;
        }
        return out;
    }

    static List<Node> children(byte[] v) {
        return children(new Node(v, 0, 0, 0, v.length));
    }

    static Node at(List<Node> l, int i) {
        return i < l.size() ? l.get(i) : null;
    }

    static Node expect(Node n, int tag, String what) {
        if (n == null || n.tag != tag) throw new Error("asn1: expected " + what);
        return n;
    }

    /** Longest OID accepted (bytes); larger ones are rejected (bounded work on hostile input). */
    static final int MAX_OID_BYTES = 128;

    /** OID contents → "1.2.3". At most {@link #MAX_OID_BYTES} bytes and 63-bit arcs, else {@link Error}. */
    static String oidString(byte[] v) {
        if (v.length > MAX_OID_BYTES) throw new Error("asn1: OID too long");
        List<Long> out = new ArrayList<>();
        long cur = 0;
        for (byte x : v) {
            if ((cur >>> 56) != 0) throw new Error("asn1: OID arc too large");
            cur = (cur << 7) | (x & 0x7f);
            if ((x & 0x80) == 0) {
                out.add(cur);
                cur = 0;
            }
        }
        if (out.isEmpty()) return "";
        long first = out.get(0);
        long a = first < 40 ? 0 : first < 80 ? 1 : 2;
        StringBuilder s = new StringBuilder().append(a).append('.').append(first - a * 40);
        for (int i = 1; i < out.size(); i++) s.append('.').append(out.get(i));
        return s.toString();
    }

    static String oid(Node n) {
        if (n.length() > MAX_OID_BYTES) throw new Error("asn1: OID too long");
        return oidString(n.value());
    }

    /** INTEGER contents (two's complement) → BigInteger. */
    static BigInteger intValue(byte[] v) {
        if (v.length == 0) throw new Error("asn1: empty INTEGER");
        return new BigInteger(v);
    }

    private static final Pattern UTC = Pattern.compile("^(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(Z|[+-]\\d{4})$");
    private static final Pattern GEN = Pattern.compile("^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\.\\d+)?(Z|[+-]\\d{4})$");

    /**
     * TS parsePreciseTime: UTCTime / GeneralizedTime → instant with the fraction kept to the nanosecond (TS keeps
     * milliseconds in the Date and the nanos separately; the Go report shows the nanos).
     */
    static Instant preciseTime(Node n) {
        String s = new String(n.buf, n.vs, n.length(), StandardCharsets.ISO_8859_1);
        Matcher m;
        int y;
        String sec;
        String frac = "";
        String z;
        if (n.tag == UTC_TIME) {
            m = UTC.matcher(s);
            if (!m.matches()) throw new Error("asn1: bad UTCTime");
            y = Integer.parseInt(m.group(1));
            y += y < 50 ? 2000 : 1900;
            sec = m.group(6) == null ? "00" : m.group(6);
            z = m.group(7);
        } else if (n.tag == GENERALIZED_TIME) {
            m = GEN.matcher(s);
            if (!m.matches()) throw new Error("asn1: bad GeneralizedTime");
            y = Integer.parseInt(m.group(1));
            sec = m.group(6);
            if (m.group(7) != null) frac = m.group(7).substring(1);
            z = m.group(8);
        } else {
            throw new Error("asn1: expected a time");
        }
        // JS Date.UTC normalises out-of-range fields (month 13 → next year); keep that.
        long t;
        try {
            LocalDateTime base = LocalDateTime.of(y, 1, 1, 0, 0);
            t = base.plusMonths(Integer.parseInt(m.group(2)) - 1L).plusDays(Integer.parseInt(m.group(3)) - 1L)
                .plusHours(Integer.parseInt(m.group(4))).plusMinutes(Integer.parseInt(m.group(5))).plusSeconds(Integer.parseInt(sec))
                .toEpochSecond(ZoneOffset.UTC);
        } catch (RuntimeException e) {
            throw new Error("asn1: bad time");
        }
        if (!z.equals("Z")) {
            long off = (Integer.parseInt(z.substring(1, 3)) * 60L + Integer.parseInt(z.substring(3, 5))) * 60L;
            t += z.charAt(0) == '+' ? -off : off;
        }
        int nanos = frac.isEmpty() ? 0 : Integer.parseInt((frac + "000000000").substring(0, 9));
        // TS: the Date carries floor(fraction × 1000) ms; GoTime takes the Date's whole seconds plus the nanos.
        return Instant.ofEpochSecond(t, nanos);
    }
}
