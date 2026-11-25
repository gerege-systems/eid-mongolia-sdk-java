package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/** Minimal DER (X.690) reader/writer — only what CMS/TSP/OCSP/X.509 parsing in this library needs. */
final class Der {
    static final int BOOLEAN = 0x01;
    static final int INTEGER = 0x02;
    static final int BIT_STRING = 0x03;
    static final int OCTET_STRING = 0x04;
    static final int NULL = 0x05;
    static final int OID = 0x06;
    static final int ENUMERATED = 0x0a;
    static final int UTF8_STRING = 0x0c;
    static final int PRINTABLE_STRING = 0x13;
    static final int T61_STRING = 0x14;
    static final int IA5_STRING = 0x16;
    static final int UTC_TIME = 0x17;
    static final int GENERALIZED_TIME = 0x18;
    static final int BMP_STRING = 0x1e;
    static final int SEQUENCE = 0x30;
    static final int SET = 0x31;

    private Der() {
    }

    static int ctx(int n) {
        return ctx(n, true);
    }

    static int ctx(int n, boolean constructed) {
        return 0x80 | (constructed ? 0x20 : 0) | n;
    }

    /** One TLV element (single-byte tags only — enough for every structure parsed here). */
    static final class Tlv {
        final byte[] buf;
        final int tag;
        final int start;
        final int valueStart;
        final int end;

        Tlv(byte[] buf, int tag, int start, int valueStart, int end) {
            this.buf = buf;
            this.tag = tag;
            this.start = start;
            this.valueStart = valueStart;
            this.end = end;
        }

        int length() {
            return end - valueStart;
        }

        byte[] value() {
            return Arrays.copyOfRange(buf, valueStart, end);
        }

        byte[] encoded() {
            return Arrays.copyOfRange(buf, start, end);
        }

        List<Tlv> children() {
            return parseAll(buf, valueStart, end);
        }

        Tlv child(int i) {
            return children().get(i);
        }

        BigInteger bigInt() {
            return new BigInteger(value());
        }

        String oid() {
            return decodeOid(buf, valueStart, end);
        }
    }

    static Tlv parse(byte[] b) {
        return parse(b, 0, b.length);
    }

    static Tlv parse(byte[] b, int off, int limit) {
        if (off + 2 > limit) throw new IllegalArgumentException("DER truncated");
        int tag = b[off] & 0xff;
        if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("DER multi-byte tag");
        int p = off + 1;
        int first = b[p++] & 0xff;
        int len;
        if (first < 0x80) {
            len = first;
        } else {
            int n = first & 0x7f;
            if (n < 1 || n > 4) throw new IllegalArgumentException("DER length");
            long l = 0;
            for (int k = 0; k < n; k++) {
                if (p >= limit) throw new IllegalArgumentException("DER truncated");
                l = (l << 8) | (b[p++] & 0xffL);
            }
            if (l > Integer.MAX_VALUE) throw new IllegalArgumentException("DER length");
            len = (int) l;
        }
        if (len < 0 || (long) p + len > limit) throw new IllegalArgumentException("DER truncated");
        return new Tlv(b, tag, off, p, p + len);
    }

    static List<Tlv> parseAll(byte[] b, int off, int end) {
        List<Tlv> out = new ArrayList<>();
        int p = off;
        while (p < end) {
            Tlv t = parse(b, p, end);
            out.add(t);
            p = t.end;
        }
        return out;
    }

    private static String decodeOid(byte[] b, int s, int e) {
        List<Long> parts = new ArrayList<>();
        long v = 0;
        for (int i = s; i < e; i++) {
            int c = b[i] & 0xff;
            v = (v << 7) | (c & 0x7f);
            if ((c & 0x80) == 0) {
                parts.add(v);
                v = 0;
            }
        }
        if (parts.isEmpty()) throw new IllegalArgumentException("OID empty");
        long first = parts.get(0);
        long a;
        long bb;
        if (first < 40) {
            a = 0;
            bb = first;
        } else if (first < 80) {
            a = 1;
            bb = first - 40;
        } else {
            a = 2;
            bb = first - 80;
        }
        StringBuilder sb = new StringBuilder().append(a).append('.').append(bb);
        for (int i = 1; i < parts.size(); i++) sb.append('.').append(parts.get(i));
        return sb.toString();
    }

    // ── writer ──

    static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 6);
        out.write(tag);
        writeLen(out, value.length);
        out.write(value, 0, value.length);
        return out.toByteArray();
    }

    static byte[] seq(byte[]... parts) {
        return tlv(SEQUENCE, concat(parts));
    }

    static byte[] set(byte[]... parts) {
        return tlv(SET, concat(parts));
    }

    static byte[] octets(byte[] v) {
        return tlv(OCTET_STRING, v);
    }

    static byte[] nullValue() {
        return new byte[] {NULL, 0};
    }

    static byte[] bool(boolean v) {
        return new byte[] {BOOLEAN, 1, v ? (byte) 0xff : 0};
    }

    static byte[] integer(long v) {
        return tlv(INTEGER, BigInteger.valueOf(v).toByteArray());
    }

    /** Go `encoding/asn1` big.Int: minimal two's complement (Java's toByteArray is the same). */
    static byte[] integer(BigInteger v) {
        return tlv(INTEGER, v.toByteArray());
    }

    static byte[] oid(String dotted) {
        String[] s = dotted.split("\\.");
        long[] p = new long[s.length];
        for (int i = 0; i < s.length; i++) p[i] = Long.parseLong(s[i]);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, p[0] * 40 + p[1]);
        for (int i = 2; i < p.length; i++) writeBase128(out, p[i]);
        return tlv(OID, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long v) {
        List<Integer> tmp = new ArrayList<>();
        long x = v;
        tmp.add((int) (x & 0x7f));
        x >>= 7;
        while (x > 0) {
            tmp.add((int) ((x & 0x7f) | 0x80));
            x >>= 7;
        }
        for (int i = tmp.size() - 1; i >= 0; i--) out.write(tmp.get(i));
    }

    private static void writeLen(ByteArrayOutputStream out, int n) {
        if (n < 0x80) {
            out.write(n);
        } else if (n < 0x100) {
            out.write(0x81);
            out.write(n);
        } else if (n < 0x10000) {
            out.write(0x82);
            out.write(n >> 8);
            out.write(n & 0xff);
        } else if (n < 0x1000000) {
            out.write(0x83);
            out.write(n >> 16);
            out.write((n >> 8) & 0xff);
            out.write(n & 0xff);
        } else {
            out.write(0x84);
            out.write(n >>> 24);
            out.write((n >> 16) & 0xff);
            out.write((n >> 8) & 0xff);
            out.write(n & 0xff);
        }
    }

    static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] out = new byte[n];
        int o = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, o, p.length);
            o += p.length;
        }
        return out;
    }

    /** Unsigned byte-wise compare (Go `bytes.Compare`) — DER SET OF ordering. */
    static final Comparator<byte[]> BYTES_ORDER = (a, b) -> {
        int n = Math.min(a.length, b.length);
        for (int i = 0; i < n; i++) {
            int d = (a[i] & 0xff) - (b[i] & 0xff);
            if (d != 0) return d;
        }
        return a.length - b.length;
    };
}
