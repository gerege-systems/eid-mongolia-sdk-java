package mn.eidmongolia.eid.login;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.Test;

/**
 * The JDK HttpServer adapter end to end on loopback (an in-process server on 127.0.0.1, ephemeral port, stopped by the
 * test) WITH an executor as documented: a stalled client (headers, no body) does not block the others; start (JSON +
 * Set-Cookie), status with the cookie, callback without a cookie (303), the socket peer as the client IP, and the 4 KiB
 * start body cap.
 */
public class EidLoginHttpHandlerTest {

    @Test
    public void endToEndOnLoopback() throws Exception {
        EidLoginSecurityTest.Fake fake = new EidLoginSecurityTest.Fake();
        mn.eidmongolia.eid.EidClient client = mn.eidmongolia.eid.EidClient.builder(
            new mn.eidmongolia.eid.Credentials(EidLoginSecurityTest.RP_UUID, "Тест банк", "rp_sk_test")).baseUrl("https://rp-api.conformance.test")
            .transport(fake).build();
        List<String> keys = Collections.synchronizedList(new ArrayList<>());
        EidLogin login = EidLogin.builder(client).failureRedirect("/login").disablePushFloor(true).disableRevocation(true)
            .rateLimit(k -> {
                keys.add(k);
                return true;
            })
            .onSuccess((id, req) -> null).build();
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/auth/eid/", new EidLoginHttpHandler(login, EidLoginHttpHandler.ClientIp.direct()));
        // As documented: an executor (a bounded pool here — the build targets Java 17), never the dispatcher thread.
        ExecutorService pool = Executors.newFixedThreadPool(4);
        server.setExecutor(pool);
        server.start();
        Socket slow = new Socket();
        try {
            // A client that sends its headers and never its body holds ONE pool thread; everyone else is still served.
            slow.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getAddress().getPort()), 5000);
            slow.getOutputStream().write(("POST /auth/eid/start HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
                + "Content-Length: 100\r\n\r\n{").getBytes(StandardCharsets.US_ASCII));
            slow.getOutputStream().flush();

            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            HttpClient http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
            HttpResponse<String> s = http.send(HttpRequest.newBuilder(URI.create(base + "/auth/eid/start")).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString("{\"mode\":\"qr\"}")).build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(s.body(), 200, s.statusCode());
            assertEquals("no-store", s.headers().firstValue("Cache-Control").orElse(""));
            @SuppressWarnings("unchecked")
            Map<String, Object> b = (Map<String, Object>) LoginJson.parse(s.body().getBytes(StandardCharsets.UTF_8));
            assertEquals("qr", b.get("mode"));
            assertTrue(((String) b.get("qr")).startsWith("https://eid.conformance.test/dl?"));
            String setCookie = s.headers().firstValue("Set-Cookie").orElse("");
            assertTrue(setCookie, setCookie.startsWith("__Host-eid_login=" + EidLoginSecurityTest.SID + ".") && setCookie.contains("HttpOnly")
                && setCookie.contains("Secure") && setCookie.contains("SameSite=Lax"));
            assertEquals("the socket peer is the client IP (the stalled request never reached the limiter)", List.of("start:127.0.0.1"), keys);

            String cookie = setCookie.substring(0, setCookie.indexOf(';'));
            HttpResponse<String> st = http.send(HttpRequest.newBuilder(URI.create(base + "/auth/eid/status")).timeout(Duration.ofSeconds(10))
                .header("Cookie", cookie).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(200, st.statusCode());
            assertTrue(st.body(), st.body().contains("\"state\":\"PENDING\""));

            HttpResponse<String> cb = http.send(HttpRequest.newBuilder(URI.create(base + "/auth/eid/callback?sessionId=x&userChallengeVerifier=y"))
                .timeout(Duration.ofSeconds(10)).GET().build(), HttpResponse.BodyHandlers.ofString());
            assertEquals(303, cb.statusCode());
            assertEquals("/login?eid_error=expired", cb.headers().firstValue("Location").orElse(""));
            assertTrue(cb.headers().allValues("Set-Cookie").get(0).contains("Max-Age=0"));

            HttpResponse<String> big = http.send(HttpRequest.newBuilder(URI.create(base + "/auth/eid/start")).timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString("{\"mode\":\"qr\",\"x\":\"" + "a".repeat(8000) + "\"}")).build(),
                HttpResponse.BodyHandlers.ofString());
            assertEquals(400, big.statusCode());
            assertTrue(big.body().contains("invalid_body"));
        } finally {
            slow.close();
            server.stop(0);
            pool.shutdownNow();
        }
    }
}
