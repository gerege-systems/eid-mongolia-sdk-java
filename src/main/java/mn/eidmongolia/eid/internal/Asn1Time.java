package mn.eidmongolia.eid.internal;

import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** ASN.1 time → Date (UTCTime / GeneralizedTime, `Z` or ±hhmm, optional fraction truncated to ms). */
public final class Asn1Time {
    private static final Pattern UTC = Pattern.compile("^(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(?:[.,](\\d+))?(Z|[+-]\\d{4})$");
    private static final Pattern GEN = Pattern.compile("^(\\d{4})(\\d{2})(\\d{2})(\\d{2})(\\d{2})(\\d{2})?(?:[.,](\\d+))?(Z|[+-]\\d{4})$");

    private Asn1Time() {
    }

    public static Date parse(Der.Tlv t) {
        String s = new String(t.value(), StandardCharsets.US_ASCII);
        boolean utc = t.tag == Der.UTC_TIME;
        Matcher m = (utc ? UTC : GEN).matcher(s);
        if (!m.matches()) throw new IllegalArgumentException("ASN.1 time " + s);
        int year = Integer.parseInt(m.group(1));
        if (utc) year += year < 50 ? 2000 : 1900;
        // Always Gregorian: Calendar.getInstance(zone) follows the default locale (th_TH → Buddhist era, ja_JP_JP →
        // Japanese imperial) and would shift every certificate / CRL / OCSP / TSA time by centuries.
        Calendar c = new GregorianCalendar(TimeZone.getTimeZone("UTC"), Locale.ROOT);
        c.clear();
        c.set(year, Integer.parseInt(m.group(2)) - 1, Integer.parseInt(m.group(3)), Integer.parseInt(m.group(4)),
            Integer.parseInt(m.group(5)), m.group(6) == null ? 0 : Integer.parseInt(m.group(6)));
        String frac = (m.group(7) == null ? "" : m.group(7)) + "000";
        c.set(Calendar.MILLISECOND, Integer.parseInt(frac.substring(0, 3)));
        long ms = c.getTimeInMillis();
        String z = m.group(8);
        if (!z.equals("Z")) {
            int sign = z.charAt(0) == '-' ? -1 : 1;
            ms -= sign * (Integer.parseInt(z.substring(1, 3)) * 3600_000L + Integer.parseInt(z.substring(3, 5)) * 60_000L);
        }
        return new Date(ms);
    }
}
