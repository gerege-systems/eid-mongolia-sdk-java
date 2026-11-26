package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/** {@link JdkHttpTransport} against an in-process loopback server (stopped after each test). */
public class JdkHttpTransportTest {
    private HttpServer server;
    private String base;

    @Before
    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/ok", x -> {
            byte[] b = ("{\"auth\":\"" + x.getRequestHeaders().getFirst("Authorization") + "\",\"lang\":\""
                + x.getRequestHeaders().getFirst("Accept-Language") + "\",\"len\":" + x.getRequestBody().readAllBytes().length + "}")
                .getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(200, b.length);
            try (OutputStream o = x.getResponseBody()) {
                o.write(b);
            }
        });
        server.createContext("/err", x -> {
            byte[] b = "{\"error\":\"x\",\"code\":\"RATE_LIMITED\"}".getBytes(StandardCharsets.UTF_8);
            x.getResponseHeaders().add("Retry-After", "2");
            x.sendResponseHeaders(429, b.length);
            try (OutputStream o = x.getResponseBody()) {
                o.write(b);
            }
        });
        server.createContext("/big", x -> {
            x.sendResponseHeaders(200, 0); // chunked, no Content-Length
            try (OutputStream o = x.getResponseBody()) {
                byte[] chunk = new byte[64 << 10];
                for (int i = 0; i < 80; i++) o.write(chunk); // 5 MiB
            } catch (IOException ignored) {
                // the client cancelled after the limit
            }
        });
        server.createContext("/redirect", x -> {
            x.getResponseHeaders().add("Location", "/ok");
            x.sendResponseHeaders(302, -1);
            x.close();
        });
        server.createContext("/slow", x -> {
            try {
                Thread.sleep(3000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            x.sendResponseHeaders(200, -1);
            x.close();
        });
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "test-http");
            t.setDaemon(true);
            return t;
        }));
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @After
    public void stop() {
        server.stop(0);
    }

    private EidClient client(Duration timeout) {
        return EidClient.builder(new Credentials("rp", "RP", "rp_sk_t")).baseUrl(base).language("mn").timeout(timeout).build();
    }

    @Test
    public void okAndHeaders() {
        RpHttp.Result r = client(null).http().postJson("/ok", Map.of("a", "б"), null);
        Json.Obj o = r.obj("x");
        assertEquals("Bearer rp_sk_t", o.optString("auth"));
        assertEquals("mn", o.optString("lang"));
        assertEquals(10, o.optLong("len", 0)); // {"a":"б"} = 10 bytes
    }

    @Test
    public void errorStatusReturnedToClient() {
        try {
            client(null).http().getJson("/err", null);
            fail();
        } catch (EidException.Api e) {
            assertEquals(429, e.status());
            assertTrue(e.retryable());
            assertEquals(Duration.ofSeconds(2), e.retryAfter());
        }
    }

    @Test
    public void bodyLimit() throws IOException {
        EidHttpResponse r = JdkHttpTransport.create().send(new EidHttpRequest("GET", URI.create(base + "/big"), Map.of(), null,
            Duration.ofSeconds(10), 1000));
        assertEquals(1001, r.body().length);
        try {
            client(null).http().getJson("/big", null);
            fail();
        } catch (EidException.ResponseTooLarge expected) {
            // ok
        }
    }

    @Test
    public void noRedirects() {
        try {
            client(null).http().getJson("/redirect", null);
            fail();
        } catch (EidException.Api e) {
            assertEquals(302, e.status());
        }
        try {
            JdkHttpTransport.of(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build());
            fail();
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }

    @Test
    public void totalDeadline() {
        long t0 = System.nanoTime();
        try {
            client(Duration.ofMillis(300)).http().getJson("/slow", null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.timeout());
            assertTrue(e.getCause() instanceof HttpTimeoutException);
        }
        assertTrue("deadline", System.nanoTime() - t0 < 2_500_000_000L);
    }

    @Test
    public void interruptCancels() throws Exception {
        EidClient c = client(Duration.ofSeconds(10));
        Thread caller = Thread.currentThread();
        Thread killer = new Thread(() -> {
            try {
                Thread.sleep(200);
            } catch (InterruptedException ignored) {
                return;
            }
            caller.interrupt();
        });
        killer.start();
        long t0 = System.nanoTime();
        try {
            c.http().getJson("/slow", null);
            fail();
        } catch (EidException.Network e) {
            assertTrue(e.cancelled());
            assertTrue(Thread.interrupted());
        } finally {
            killer.join();
        }
        assertTrue("interrupt", System.nanoTime() - t0 < 2_500_000_000L);
    }
}
