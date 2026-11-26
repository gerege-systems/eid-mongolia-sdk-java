package mn.eidmongolia.eid;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.net.ssl.SSLContext;

/**
 * The default {@link EidTransport} over {@link java.net.http.HttpClient}: no redirects, a total deadline per request
 * (connect + headers + body, like Go {@code http.Client} with a context deadline), the body read up to the request's
 * limit + 1 bytes (a larger Content-Length is not read at all), and {@link Thread#interrupt()} cancels the exchange.
 * Thread-safe; share one instance.
 */
public final class JdkHttpTransport implements EidTransport {
    private final HttpClient client;

    private JdkHttpTransport(HttpClient client) {
        this.client = client;
    }

    /** A transport with the JDK's default TLS settings. */
    public static JdkHttpTransport create() {
        return new JdkHttpTransport(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
    }

    /**
     * mTLS (or a private trust store): an {@link SSLContext} initialised with the RP's client certificate key manager.
     */
    public static JdkHttpTransport create(SSLContext sslContext) {
        Objects.requireNonNull(sslContext, "sslContext");
        return new JdkHttpTransport(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).sslContext(sslContext).build());
    }

    /**
     * A caller-configured client (proxy, executor, mTLS). It MUST use {@link HttpClient.Redirect#NEVER} — a redirect
     * would carry the API secret elsewhere; this is rejected.
     */
    public static JdkHttpTransport of(HttpClient client) {
        Objects.requireNonNull(client, "client");
        if (client.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("eid: HttpClient must use Redirect.NEVER (the Authorization header must not follow redirects)");
        }
        return new JdkHttpTransport(client);
    }

    @Override
    public EidHttpResponse send(EidHttpRequest req) throws IOException {
        HttpRequest.Builder b = HttpRequest.newBuilder(req.uri()).timeout(req.timeout());
        for (Map.Entry<String, String> h : req.headers().entrySet()) b.header(h.getKey(), h.getValue());
        b.method(req.method(), req.body() == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(req.body()));
        long limit = req.maxResponseBytes();
        CompletableFuture<HttpResponse<byte[]>> f = client.sendAsync(b.build(), info -> new Limited(info, limit));
        HttpResponse<byte[]> res;
        try {
            res = f.get(req.timeout().toNanos(), TimeUnit.NANOSECONDS);
        } catch (TimeoutException e) {
            f.cancel(true);
            throw new HttpTimeoutException("timeout after " + req.timeout().toMillis() + " ms");
        } catch (InterruptedException e) {
            f.cancel(true);
            Thread.currentThread().interrupt();
            InterruptedIOException x = new InterruptedIOException("interrupted");
            x.initCause(e);
            throw x;
        } catch (ExecutionException e) {
            Throwable c = e.getCause();
            if (c instanceof IOException) throw (IOException) c;
            throw new IOException(String.valueOf(c), c);
        }
        return new EidHttpResponse(res.statusCode(), res.headers().map(), res.body());
    }

    /** Collects the body up to limit + 1 bytes, then cancels; a declared Content-Length above the limit is not read. */
    static final class Limited implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> result = new CompletableFuture<>();
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();
        private final long limit;
        private final boolean declaredTooLarge;
        private Flow.Subscription sub;

        Limited(HttpResponse.ResponseInfo info, long limit) {
            this.limit = limit;
            this.declaredTooLarge = info.headers().firstValueAsLong("content-length").orElse(-1) > limit;
        }

        @Override
        public CompletionStage<byte[]> getBody() {
            return result;
        }

        @Override
        public void onSubscribe(Flow.Subscription s) {
            sub = s;
            if (declaredTooLarge) {
                s.cancel(); // the client rejects it by the Content-Length header
                result.complete(new byte[0]);
                return;
            }
            s.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(List<ByteBuffer> items) {
            if (result.isDone()) return;
            for (ByteBuffer bb : items) {
                int room = (int) Math.min(bb.remaining(), limit + 1 - out.size());
                byte[] chunk = new byte[room];
                bb.get(chunk);
                out.write(chunk, 0, room);
                if (out.size() > limit) {
                    sub.cancel();
                    result.complete(out.toByteArray());
                    return;
                }
            }
        }

        @Override
        public void onError(Throwable t) {
            result.completeExceptionally(t);
        }

        @Override
        public void onComplete() {
            result.complete(out.toByteArray());
        }
    }
}
