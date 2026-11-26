package mn.eidmongolia.eid.pades.validate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Byte-identical Go report values (TS src/pades/validate/gofmt.ts): time.Time MarshalJSON (RFC3339Nano, UTC),
 * pkix.Name.String(), big.Int.Text(16), digitorus pdf Value.Text(), Go's UTF-8 repair in encoding/json.
 */
final class GoFmt {
    private GoFmt() {
    }

    static boolean isZero(Instant t) {
        return t.equals(Asn1.ZERO);
    }

    /** Go time.Time.MarshalJSON in UTC: "2006-01-02T15:04:05.999999999Z". */
    static String formatTime(Instant t) {
        if (isZero(t)) return "0001-01-01T00:00:00Z";
        ZonedDateTime d = t.atZone(ZoneOffset.UTC);
        StringBuilder s = new StringBuilder(String.format("%04d-%02d-%02dT%02d:%02d:%02d", d.getYear(), d.getMonthValue(),
            d.getDayOfMonth(), d.getHour(), d.getMinute(), d.getSecond()));
        int n = t.getNano();
        if (n > 0) {
            String f = String.format("%09d", n);
            int e = f.length();
            while (e > 0 && f.charAt(e - 1) == '0') e--;
            s.append('.').append(f, 0, e);
        }
        return s.append('Z').toString();
    }

    /** big.Int.Text(16) upper-cased (CA hexSerial): INTEGER contents → "1A2B". */
    static String hexSerial(byte[] intContent) {
        BigInteger v = intContent.length == 0 ? BigInteger.ZERO : new BigInteger(intContent);
        String s = v.abs().toString(16).toUpperCase(java.util.Locale.ROOT);
        return v.signum() < 0 ? "-" + s : s;
    }

    static String hexSerial(BigInteger v) {
        String s = v.abs().toString(16).toUpperCase(java.util.Locale.ROOT);
        return v.signum() < 0 ? "-" + s : s;
    }

    private static final int NO_RUNE = -1;
    // digitorus/pdf text.go pdfDocEncoding (PDF 32000-1 Table D.2).
    private static final int[] PDF_DOC = new int[256];

    static {
        Arrays.fill(PDF_DOC, NO_RUNE);
        PDF_DOC[9] = 9;
        PDF_DOC[10] = 10;
        PDF_DOC[13] = 13;
        int[] a = {0x02d8, 0x02c7, 0x02c6, 0x02d9, 0x02dd, 0x02db, 0x02da, 0x02dc};
        for (int i = 0; i < a.length; i++) PDF_DOC[0x18 + i] = a[i];
        for (int i = 0x20; i < 0x7f; i++) PDF_DOC[i] = i;
        int[] b = {0x2022, 0x2020, 0x2021, 0x2026, 0x2014, 0x2013, 0x0192, 0x2044, 0x2039, 0x203a, 0x2212, 0x2030, 0x201e, 0x201c,
            0x201d, 0x2018, 0x2019, 0x201a, 0x2122, 0xfb01, 0xfb02, 0x0141, 0x0152, 0x0160, 0x0178, 0x017d, 0x0131, 0x0142, 0x0153,
            0x0161, 0x017e, NO_RUNE};
        for (int i = 0; i < b.length; i++) PDF_DOC[0x80 + i] = b[i];
        PDF_DOC[0xa0] = 0x20ac;
        for (int i = 0xa1; i <= 0xff; i++) PDF_DOC[i] = i;
        PDF_DOC[0xad] = NO_RUNE;
    }

    /** digitorus pdf Value.Text(): PDFDocEncoding → UTF-16BE (BOM, even length) → raw bytes (Go string). */
    static String pdfText(byte[] b) {
        boolean utf16 = b.length >= 2 && (b[0] & 0xff) == 0xfe && (b[1] & 0xff) == 0xff && b.length % 2 == 0;
        if (!utf16) {
            boolean all = true;
            for (byte x : b) {
                if (PDF_DOC[x & 0xff] == NO_RUNE) {
                    all = false;
                    break;
                }
            }
            if (all) {
                StringBuilder s = new StringBuilder();
                for (byte x : b) s.appendCodePoint(PDF_DOC[x & 0xff]);
                return s.toString();
            }
            return goString(b, 0, b.length);
        }
        char[] u = new char[(b.length - 2) / 2];
        for (int i = 2, k = 0; i < b.length; i += 2, k++) u[k] = (char) (((b[i] & 0xff) << 8) | (b[i + 1] & 0xff));
        return fixSurrogates(new String(u));
    }

    /** Go utf16.Decode: an unpaired surrogate → U+FFFD. */
    static String fixSurrogates(String s) {
        StringBuilder o = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                    o.append(c).append(s.charAt(i + 1));
                    i++;
                } else {
                    o.append('�');
                }
            } else if (Character.isLowSurrogate(c)) {
                o.append('�');
            } else {
                o.append(c);
            }
        }
        return o.toString();
    }

    static String goString(byte[] b) {
        return goString(b, 0, b.length);
    }

    /** Raw bytes (Go string) → the string Go's encoding/json writes: every invalid UTF-8 byte → U+FFFD. */
    static String goString(byte[] b, int from, int to) {
        StringBuilder out = new StringBuilder();
        for (int i = from; i < to; ) {
            int[] r = decodeRune(b, i, to);
            out.appendCodePoint(r[0]);
            i += r[1];
        }
        return out.toString();
    }

    private static boolean cont(byte[] b, int i, int to, int k, int lo, int hi) {
        return i + k < to && (b[i + k] & 0xff) >= lo && (b[i + k] & 0xff) <= hi;
    }

    /** Go utf8.DecodeRune: (rune, size); invalid → (U+FFFD, 1). */
    static int[] decodeRune(byte[] b, int i, int to) {
        int c0 = b[i] & 0xff;
        if (c0 < 0x80) return new int[] {c0, 1};
        int[] bad = {0xfffd, 1};
        if (c0 >= 0xc2 && c0 <= 0xdf) return cont(b, i, to, 1, 0x80, 0xbf) ? new int[] {((c0 & 0x1f) << 6) | (b[i + 1] & 0x3f), 2} : bad;
        if (c0 >= 0xe0 && c0 <= 0xef) {
            int lo = c0 == 0xe0 ? 0xa0 : 0x80;
            int hi = c0 == 0xed ? 0x9f : 0xbf;
            return cont(b, i, to, 1, lo, hi) && cont(b, i, to, 2, 0x80, 0xbf)
                ? new int[] {((c0 & 0x0f) << 12) | ((b[i + 1] & 0x3f) << 6) | (b[i + 2] & 0x3f), 3} : bad;
        }
        if (c0 >= 0xf0 && c0 <= 0xf4) {
            int lo = c0 == 0xf0 ? 0x90 : 0x80;
            int hi = c0 == 0xf4 ? 0x8f : 0xbf;
            return cont(b, i, to, 1, lo, hi) && cont(b, i, to, 2, 0x80, 0xbf) && cont(b, i, to, 3, 0x80, 0xbf)
                ? new int[] {((c0 & 0x07) << 18) | ((b[i + 1] & 0x3f) << 12) | ((b[i + 2] & 0x3f) << 6) | (b[i + 3] & 0x3f), 4} : bad;
        }
        return bad;
    }

    // ── pkix.Name ──

    private static final class Atv {
        final String oid;
        /** Go asn1 interface{} decoding: a string for the string types, else null. */
        final String str;
        final byte[] raw;

        Atv(String oid, String str, byte[] raw) {
            this.oid = oid;
            this.str = str;
            this.raw = raw;
        }
    }

    private static final Map<String, String> ATTR_NAMES = new LinkedHashMap<>();

    static {
        ATTR_NAMES.put("2.5.4.6", "C");
        ATTR_NAMES.put("2.5.4.10", "O");
        ATTR_NAMES.put("2.5.4.11", "OU");
        ATTR_NAMES.put("2.5.4.3", "CN");
        ATTR_NAMES.put("2.5.4.5", "SERIALNUMBER");
        ATTR_NAMES.put("2.5.4.7", "L");
        ATTR_NAMES.put("2.5.4.8", "ST");
        ATTR_NAMES.put("2.5.4.9", "STREET");
        ATTR_NAMES.put("2.5.4.17", "POSTALCODE");
    }

    private static String asn1String(Asn1.Node n) {
        switch (n.tag) {
            case Asn1.PRINTABLE:
            case Asn1.IA5:
            case 0x12:
            case 0x14:
            case Asn1.UTF8:
                return goString(n.buf, n.vs, n.end);
            case 0x1e: {
                if (n.length() % 2 != 0) return null;
                int len = n.length() / 2;
                char[] u = new char[len];
                for (int i = 0; i < len; i++) u[i] = (char) (((n.buf[n.vs + 2 * i] & 0xff) << 8) | (n.buf[n.vs + 2 * i + 1] & 0xff));
                if (len > 0 && u[len - 1] == 0) len--;
                return fixSurrogates(new String(u, 0, len));
            }
            default:
                return null;
        }
    }

    private static List<List<Atv>> rdns(byte[] name) {
        List<List<Atv>> out = new ArrayList<>();
        for (Asn1.Node rdn : Asn1.children(Asn1.readNode(name, 0))) {
            List<Atv> l = new ArrayList<>();
            for (Asn1.Node atv : Asn1.children(rdn)) {
                List<Asn1.Node> tv = Asn1.children(atv);
                Asn1.Node t = tv.get(0);
                Asn1.Node v = tv.get(1);
                l.add(new Atv(Asn1.oid(t), asn1String(v), v.raw()));
            }
            out.add(l);
        }
        return out;
    }

    /** Go asn1.Marshal(string): PrintableString (allowed characters) or UTF8String. */
    private static byte[] marshalString(String s) {
        byte[] bytes = s.getBytes(StandardCharsets.UTF_8);
        boolean printable = true;
        for (int i = 0; i < s.length(); ) {
            int c = s.codePointAt(i);
            i += Character.charCount(c);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || " '()+,-./:=?".indexOf(c) >= 0;
            if (!ok) {
                printable = false;
                break;
            }
        }
        int tag = printable ? Asn1.PRINTABLE : Asn1.UTF8;
        int len = bytes.length;
        byte[] hdr = len < 0x80 ? new byte[] {(byte) tag, (byte) len}
            : len < 0x100 ? new byte[] {(byte) tag, (byte) 0x81, (byte) len} : new byte[] {(byte) tag, (byte) 0x82, (byte) (len >> 8), (byte) len};
        byte[] out = Arrays.copyOf(hdr, hdr.length + len);
        System.arraycopy(bytes, 0, out, hdr.length, len);
        return out;
    }

    private static final Set<String> SKIP = new HashSet<>(List.of("2.5.4.3", "2.5.4.5", "2.5.4.6", "2.5.4.7", "2.5.4.8", "2.5.4.9", "2.5.4.10",
        "2.5.4.11", "2.5.4.17"));

    /** Go pkix.Name.String() of a parsed certificate's Subject / Issuer (ExtraNames nil). */
    static String nameString(byte[] rawName) {
        List<List<Atv>> seq = rdns(rawName);
        Map<String, List<String>> f = new LinkedHashMap<>();
        for (String k : new String[] {"C", "ST", "L", "STREET", "POSTALCODE", "O", "OU"}) f.put(k, new ArrayList<>());
        String cn = "";
        String sn = "";
        List<Atv> all = new ArrayList<>();
        for (List<Atv> rdn : seq) {
            for (Atv a : rdn) {
                all.add(a);
                if (a.str == null) continue;
                switch (a.oid) {
                    case "2.5.4.3": cn = a.str; break;
                    case "2.5.4.5": sn = a.str; break;
                    case "2.5.4.6": f.get("C").add(a.str); break;
                    case "2.5.4.7": f.get("L").add(a.str); break;
                    case "2.5.4.8": f.get("ST").add(a.str); break;
                    case "2.5.4.9": f.get("STREET").add(a.str); break;
                    case "2.5.4.17": f.get("POSTALCODE").add(a.str); break;
                    case "2.5.4.10": f.get("O").add(a.str); break;
                    case "2.5.4.11": f.get("OU").add(a.str); break;
                    default: break;
                }
            }
        }
        List<List<Atv>> out = new ArrayList<>();
        for (Atv a : all) if (!SKIP.contains(a.oid)) out.add(List.of(a));
        add(out, f.get("C"), "2.5.4.6");
        add(out, f.get("ST"), "2.5.4.8");
        add(out, f.get("L"), "2.5.4.7");
        add(out, f.get("STREET"), "2.5.4.9");
        add(out, f.get("POSTALCODE"), "2.5.4.17");
        add(out, f.get("O"), "2.5.4.10");
        add(out, f.get("OU"), "2.5.4.11");
        if (!cn.isEmpty()) add(out, List.of(cn), "2.5.4.3");
        if (!sn.isEmpty()) add(out, List.of(sn), "2.5.4.5");
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < out.size(); i++) {
            List<Atv> rdn = out.get(out.size() - 1 - i);
            if (i > 0) s.append(',');
            for (int j = 0; j < rdn.size(); j++) {
                Atv tv = rdn.get(j);
                if (j > 0) s.append('+');
                String typeName = ATTR_NAMES.get(tv.oid);
                if (typeName == null) {
                    byte[] der = tv.str != null ? marshalString(tv.str) : tv.raw;
                    s.append(tv.oid).append("=#").append(mn.eidmongolia.eid.internal.Text.hex(der));
                    continue;
                }
                String v = tv.str == null ? "" : tv.str;
                int lastByte = v.getBytes(StandardCharsets.UTF_8).length - 1;
                int byteIdx = 0;
                StringBuilder esc = new StringBuilder();
                for (int k = 0; k < v.length(); ) {
                    int c = v.codePointAt(k);
                    k += Character.charCount(c);
                    boolean e;
                    if (",+\"\\<>;".indexOf(c) >= 0) e = true;
                    else if (c == ' ') e = byteIdx == 0 || byteIdx == lastByte;
                    else if (c == '#') e = byteIdx == 0;
                    else e = false;
                    if (e) esc.append('\\');
                    esc.appendCodePoint(c);
                    byteIdx += new String(Character.toChars(c)).getBytes(StandardCharsets.UTF_8).length;
                }
                s.append(typeName).append('=').append(esc);
            }
        }
        return s.toString();
    }

    private static void add(List<List<Atv>> out, List<String> vals, String oid) {
        if (vals.isEmpty()) return;
        List<Atv> l = new ArrayList<>();
        for (String v : vals) l.add(new Atv(oid, v, null));
        out.add(l);
    }

    /** Go pkix.Name.CommonName (the last string CN). */
    static String commonName(byte[] rawName) {
        return lastString(rawName, "2.5.4.3");
    }

    /** Go pkix.Name.SerialNumber (the last string SERIALNUMBER). */
    static String subjectSerialNumber(byte[] rawSubject) {
        return lastString(rawSubject, "2.5.4.5");
    }

    private static String lastString(byte[] rawName, String oid) {
        String v = "";
        for (List<Atv> rdn : rdns(rawName)) for (Atv a : rdn) if (a.oid.equals(oid) && a.str != null) v = a.str;
        return v;
    }

    /** eidcrypto.SubjectNames: the last GIVENNAME / SURNAME ("" when not a string). */
    static String[] subjectNames(byte[] rawSubject) {
        String given = "";
        String surname = "";
        for (List<Atv> rdn : rdns(rawSubject)) {
            for (Atv a : rdn) {
                if (a.oid.equals("2.5.4.42")) given = a.str == null ? "" : a.str;
                if (a.oid.equals("2.5.4.4")) surname = a.str == null ? "" : a.str;
            }
        }
        return new String[] {given, surname};
    }
}
