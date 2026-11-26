package mn.eidmongolia.eid;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Locale;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Device link v3 (Smart-ID RP-API v3 «dynamic link»; Go {@code devicelink.go}, TS {@code devicelinkv3.ts}): the RP
 * BACKEND builds the QR / Web2App / App2App link, protected by authCode = HMAC-SHA256(sessionSecret); a QR link's
 * elapsedSeconds changes every second. Never send sessionSecret to a browser/app — serve the QR from a backend
 * endpoint every second.
 */
public final class DeviceLink {
    private static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern LANG = Pattern.compile("[a-z]{3}");
    private static final Pattern STD_B64 = Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");

    private DeviceLink() {
    }

    private static EidException.DeviceLink err(String m) {
        return new EidException.DeviceLink(m);
    }

    /**
     * Builds the complete device link (…&amp;authCode=…). A pure function.
     *
     * <pre>
     * QR:      {base}?deviceLinkType=QR&amp;elapsedSeconds={E}&amp;sessionToken={T}&amp;sessionType={S}&amp;version=1.0&amp;lang={L}&amp;authCode={A}
     * Web2App: {base}?deviceLinkType=Web2App&amp;sessionToken={T}&amp;sessionType={S}&amp;version=1.0&amp;lang={L}&amp;authCode={A}
     * </pre>
     *
     * A QR link expires in ~20 s — rebuild and show it every second. Build Web2App/App2App links once.
     *
     * @throws EidException.DeviceLink on invalid input
     */
    public static String build(DeviceLinkInput p) {
        String base = p.deviceLinkBase.strip();
        if (base.isEmpty()) throw err("deviceLinkBase хоосон — device-link session-ий хариуг шалга");
        URI u;
        try {
            u = new URI(base);
        } catch (URISyntaxException e) {
            throw err("deviceLinkBase буруу URL: " + base);
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String authority = u.getRawAuthority();
        if (!scheme.equals("https") || authority == null || authority.isEmpty() || base.indexOf('?') >= 0 || base.indexOf('#') >= 0) {
            throw err("deviceLinkBase нь query/fragment-гүй https URL байх ёстой");
        }
        if (p.deviceLinkType == null) throw err("deviceLinkType (QR | Web2App | App2App)");
        if (p.sessionType == null) throw err("sessionType (auth | sign | cert)");
        if (!TOKEN.matcher(p.sessionToken).matches()) throw err("sessionToken хэлбэр буруу");
        if (!LANG.matcher(p.lang).matches()) throw err("lang нь ISO 639-2 гурван жижиг үсэг (mon, eng)");
        if (p.sessionSecret.isEmpty() || !STD_B64.matcher(p.sessionSecret).matches()) {
            throw err("sessionSecret стандарт Base64 (padding-тэй) биш");
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(p.sessionSecret);
        } catch (IllegalArgumentException e) {
            throw err("sessionSecret стандарт Base64 (padding-тэй) биш");
        }

        String challenge;
        switch (p.sessionType) {
            case AUTH:
                if (p.rpChallenge.isEmpty()) throw err("auth session-д rpChallenge заавал");
                challenge = p.rpChallenge;
                break;
            case SIGN:
                if (p.digest.isEmpty()) throw err("sign session-д digest заавал");
                challenge = p.digest;
                break;
            default:
                if (!p.rpChallenge.isEmpty() || !p.digest.isEmpty()) throw err("cert session-д rpChallenge/digest байхгүй");
                challenge = "";
        }

        boolean qr = p.deviceLinkType == DeviceLinkType.QR;
        String callback = "";
        if (!qr) {
            callback = p.initialCallbackUrl;
            if (callback.isEmpty()) throw err(p.deviceLinkType.wireName() + " холбоос initialCallbackUrl-тай session-д л хүчинтэй");
        }

        String elapsed = "";
        if (qr) {
            if (p.receivedAt == null) throw err("QR холбоосонд receivedAt заавал");
            Instant now = p.now == null ? Instant.now() : p.now;
            // A clock stepping back (NTP) never yields a negative value — the server rejects a future elapsed.
            Duration d = Duration.between(p.receivedAt, now);
            long e = d.isNegative() ? 0 : d.getSeconds();
            elapsed = "&elapsedSeconds=" + e;
        }

        String unprotected = base + "?deviceLinkType=" + p.deviceLinkType.wireName() + elapsed
            + "&sessionToken=" + p.sessionToken + "&sessionType=" + p.sessionType.wireName()
            + "&version=1.0&lang=" + p.lang;
        String schemeName = p.schemeName.isEmpty() ? "smart-id" : p.schemeName;
        String payload = String.join("|", schemeName, p.sessionType.protocol(), challenge, Acsp.b64(p.relyingPartyName),
            Acsp.b64(p.brokeredRpName), p.interactions, callback, unprotected);
        byte[] mac;
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            mac = m.doFinal(EidCrypto.utf8(payload));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException("HmacSHA256", e);
        }
        return unprotected + "&authCode=" + Base64.getUrlEncoder().withoutPadding().encodeToString(mac);
    }

    /**
     * For SSE / WebSocket (Go {@code TickQRDeviceLink}, TS {@code qrDeviceLinkTicker}): emits the QR link to
     * {@code onLink} at once, then every {@code interval} (null / ≤ 0 = 1 s), blocking the calling thread until it is
     * interrupted (end of session / client gone: interrupt the thread, e.g. {@code Future.cancel(true)}). Ticks missed
     * by a slow {@code onLink} are dropped, not bunched. The input's deviceLinkType is forced to QR and its {@code now} is
     * replaced by the tick time. Not needed with HTTP polling — call {@link #build} per request instead.
     *
     * @throws EidException.DeviceLink invalid input, thrown by the FIRST tick before anything is emitted
     * @throws InterruptedException when the thread is interrupted (the normal way to stop)
     */
    public static void tickQr(DeviceLinkInput input, Duration interval, Consumer<String> onLink) throws InterruptedException {
        tickQr(input, interval, onLink, Clock.systemUTC(), d -> Thread.sleep(d.toMillis(), d.toNanosPart() % 1_000_000));
    }

    /** Sleeps for a duration (tests replace it with a fake clock). */
    @FunctionalInterface
    interface Sleeper {
        void sleep(Duration d) throws InterruptedException;
    }

    static void tickQr(DeviceLinkInput input, Duration interval, Consumer<String> onLink, Clock clock, Sleeper sleeper)
        throws InterruptedException {
        Duration iv = interval == null || interval.isZero() || interval.isNegative() ? Duration.ofSeconds(1) : interval;
        DeviceLinkInput.Builder in = input.toBuilder().deviceLinkType(DeviceLinkType.QR);
        Instant start = clock.instant();
        onLink.accept(build(in.now(start).build()));
        long ivNanos = iv.toNanos();
        while (true) {
            if (Thread.interrupted()) throw new InterruptedException();
            Instant now = clock.instant();
            long elapsed = Duration.between(start, now).toNanos();
            long k = elapsed < 0 ? 1 : elapsed / ivNanos + 1; // the next tick strictly after now
            Duration wait = Duration.between(now, start.plusNanos(k * ivNanos));
            if (!wait.isZero() && !wait.isNegative()) sleeper.sleep(wait);
            if (Thread.interrupted()) throw new InterruptedException();
            onLink.accept(build(in.now(clock.instant()).build()));
        }
    }
}
