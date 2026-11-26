package mn.eidmongolia.eid.internal;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

/** Byte/text helpers with Go semantics (hex, base64, TrimSpace, ASN.1 strings). Every charset is explicit. */
public final class Text {
    private Text() {
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static byte[] latin1(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    public static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** Lowercase hex. */
    public static String hex(byte[] b) {
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            c[2 * i] = HEX[(b[i] >> 4) & 0xf];
            c[2 * i + 1] = HEX[b[i] & 0xf];
        }
        return new String(c);
    }

    /** PDF hex string «<…>», lowercase. */
    public static String hexString(byte[] raw) {
        return "<" + hex(raw) + ">";
    }

    /** -1 when [c] is not a hex digit. */
    public static int hexVal(int c) {
        if (c >= 0x30 && c <= 0x39) return c - 0x30;
        if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10;
        if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10;
        return -1;
    }

    /** Strict even-length hex decode of b[from, to); null on any non-hex char. */
    public static byte[] unhex(byte[] b, int from, int to) {
        if ((to - from) % 2 != 0) return null;
        byte[] out = new byte[(to - from) / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = hexVal(b[from + 2 * i] & 0xff);
            int lo = hexVal(b[from + 2 * i + 1] & 0xff);
            if (hi < 0 || lo < 0) return null;
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static byte[] unhex(String s) {
        byte[] b = latin1(s);
        byte[] out = unhex(b, 0, b.length);
        if (out == null) throw new IllegalArgumentException("hex");
        return out;
    }

    private static final String B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /** RFC 4648 standard base64 with padding (Go encoding/json []byte). */
    public static String base64(byte[] b) {
        return java.util.Base64.getEncoder().encodeToString(b);
    }

    /** Decodes standard base64, ignoring whitespace (PEM bodies), stopping at '='. */
    public static byte[] unbase64(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() * 3 / 4);
        int v = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '=') break;
            if (Character.isWhitespace(ch)) continue;
            int x = B64.indexOf(ch);
            if (x < 0) throw new IllegalArgumentException("base64");
            v = (v << 6) | x;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((v >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }

    /** Go `unicode.IsSpace`. */
    public static boolean isSpace(int c) {
        switch (c) {
            case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x20: case 0x85: case 0xa0: case 0x1680:
            case 0x2028: case 0x2029: case 0x202f: case 0x205f: case 0x3000:
                return true;
            default:
                return c >= 0x2000 && c <= 0x200a;
        }
    }

    /** Go `strings.TrimSpace`. */
    public static String trimSpace(String s) {
        int a = 0;
        int b = s.length();
        while (a < b && isSpace(s.codePointAt(a))) a += Character.charCount(s.codePointAt(a));
        while (b > a && isSpace(s.codePointBefore(b))) b -= Character.charCount(s.codePointBefore(b));
        return s.substring(a, b);
    }

    /** ASN.1 directory string → String (Go pkix value decoding for the string types X.509 names use). */
    public static String asn1(Der.Tlv t) {
        switch (t.tag) {
            case Der.BMP_STRING:
                return new String(t.value(), StandardCharsets.UTF_16BE);
            case Der.T61_STRING:
            case Der.IA5_STRING:
            case Der.PRINTABLE_STRING:
                return new String(t.value(), StandardCharsets.ISO_8859_1);
            default:
                return new String(t.value(), StandardCharsets.UTF_8);
        }
    }

    /** Lone surrogates make a string invalid UTF-8 in Go. */
    public static boolean validSurrogates(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (i + 1 >= s.length() || !Character.isLowSurrogate(s.charAt(i + 1))) return false;
                i++;
            } else if (Character.isLowSurrogate(c)) {
                return false;
            }
        }
        return true;
    }
}
