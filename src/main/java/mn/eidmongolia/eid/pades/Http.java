package mn.eidmongolia.eid.pades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Go fetch.go defaultHTTPClient: 10 s TOTAL per request (connect + send + headers + body — Go `http.Client.Timeout`,
 * not a per-read idle timeout), no redirects, 200 only, ≤ 4 MiB. The exchange runs on its own daemon thread and the
 * caller waits at most the deadline, so a server trickling bytes cannot hold `complete` past it. No shared pool.
 */
final class DefaultHttp implements EidPadesTransport {
    static final DefaultHttp INSTANCE = new DefaultHttp();
    private static final long TIMEOUT_MS = 10_000L;
    static final int MAX_RESPONSE = 4 << 20;

    private DefaultHttp() {
    }

    @Override
    public byte[] send(String method, String url, String contentType, byte[] body) throws IOException {
        return send(method, url, contentType, body, TIMEOUT_MS);
    }

    /** [timeoutMs] — the whole request's deadline (tests use a short one). */
    static byte[] send(String method, String url, String contentType, byte[] body, long timeoutMs) throws IOException {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        FutureTask<byte[]> job = new FutureTask<>(() -> exchange(c, method, url, contentType, body, timeoutMs));
        Thread t = new Thread(job, "eid-pades-http");
        t.setDaemon(true);
        t.start();
        try {
            return job.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            job.cancel(true);
            c.disconnect();
            throw new SocketTimeoutException(url + ": timeout after " + timeoutMs + " ms");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof IOException) throw (IOException) cause;
            throw new IOException(url + ": " + cause, cause);
        } catch (InterruptedException e) {
            job.cancel(true);
            c.disconnect();
            Thread.currentThread().interrupt();
            InterruptedIOException x = new InterruptedIOException(url + ": interrupted");
            x.initCause(e);
            throw x;
        }
    }

    private static byte[] exchange(HttpURLConnection c, String method, String url, String contentType, byte[] body, long timeoutMs)
        throws IOException {
        try {
            int t = (int) Math.min(timeoutMs, Integer.MAX_VALUE);
            c.setInstanceFollowRedirects(false);
            c.setConnectTimeout(t);
            c.setReadTimeout(t);
            c.setRequestMethod(method);
            if (contentType != null) c.setRequestProperty("Content-Type", contentType);
            if (body != null) {
                c.setDoOutput(true);
                c.setFixedLengthStreamingMode(body.length);
                try (OutputStream o = c.getOutputStream()) {
                    o.write(body);
                }
            }
            int code = c.getResponseCode();
            if (code != 200) throw new IOException(url + ": HTTP " + code);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (InputStream in = c.getInputStream()) {
                byte[] buf = new byte[16 << 10];
                while (true) {
                    if (Thread.currentThread().isInterrupted()) throw new InterruptedIOException(url + ": cancelled");
                    int n = in.read(buf);
                    if (n < 0) break;
                    out.write(buf, 0, n);
                    if (out.size() > MAX_RESPONSE) throw new IOException(url + ": response larger than 4 MiB");
                }
            }
            return out.toByteArray();
        } finally {
            c.disconnect();
        }
    }
}

/** Go fetcher: http/https only, national CRLs via the eID mirror (WIRE.md §3), GET responses cached per complete(). */
final class Fetcher {
    /** National CRLs (http-only, not ours) → eID https mirror; the CRL signature is checked against its issuer. */
    static final Map<String, String> CRL_MIRROR = Map.of(
        "http://esign.gov.mn/MNICA-2022.crl", "https://crl.eidmongolia.mn/MNICA-2022.crl",
        "http://esign.gov.mn/MNRCA-2021.crl", "https://crl.eidmongolia.mn/MNRCA-2021.crl");

    private final EidPadesTransport client;
    private final Map<String, byte[]> cache = new HashMap<>();

    Fetcher(EidPadesTransport client) {
        this.client = client;
    }

    byte[] get(String raw) throws IOException {
        String url = target(raw);
        byte[] hit = cache.get(url);
        if (hit != null) return hit;
        byte[] b = client.send("GET", url, null, null);
        checkSize(b);
        cache.put(url, b);
        return b;
    }

    byte[] post(String raw, String contentType, byte[] body) throws IOException {
        byte[] b = client.send("POST", target(raw), contentType, body);
        checkSize(b);
        return b;
    }

    private static String target(String raw) throws IOException {
        String m = CRL_MIRROR.get(raw);
        if (m != null) return m;
        int i = raw.indexOf(':');
        String scheme = i < 0 ? "" : raw.substring(0, i).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw new IOException("URL scheme \"" + scheme + "\" not supported");
        return raw;
    }

    private static void checkSize(byte[] b) throws IOException {
        if (b == null) throw new IOException("no response body");
        if (b.length > DefaultHttp.MAX_RESPONSE) throw new IOException("response larger than 4 MiB");
    }
}
