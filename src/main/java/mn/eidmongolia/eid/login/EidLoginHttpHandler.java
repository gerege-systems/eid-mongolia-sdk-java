package mn.eidmongolia.eid.login;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * {@link EidLogin} on the JDK's built-in server ({@code com.sun.net.httpserver}, module jdk.httpserver — no extra
 * dependency):
 *
 * <pre>{@code
 * HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
 * server.createContext("/auth/eid/", new EidLoginHttpHandler(login, EidLoginHttpHandler.ClientIp.direct()));
 * }</pre>
 *
 * The client IP for the {@code start:<ip>} limit is chosen EXPLICITLY: {@link ClientIp#direct()} (the socket peer — no
 * proxy in front), {@link ClientIp#trustedProxies(int)} (behind n trusted reverse proxies; X-Forwarded-For from the
 * right) or {@link ClientIp#none()} (no per-IP limit). Bodies are read up to 4 KiB + 1 (a larger start body is
 * {@code invalid_body}).
 */
public final class EidLoginHttpHandler implements HttpHandler {
    private static final int DRAIN_BYTES = 64 << 10;
    private final EidLogin login;
    private final ClientIp clientIp;

    /** Where the client IP comes from. */
    public static final class ClientIp {
        final Function<HttpExchange, String> socket;
        final Function<EidLoginRequest, String> headers;

        private ClientIp(Function<HttpExchange, String> socket, Function<EidLoginRequest, String> headers) {
            this.socket = socket;
            this.headers = headers;
        }

        /** The socket peer's address (clients connect directly). */
        public static ClientIp direct() {
            return new ClientIp(x -> {
                InetSocketAddress a = x.getRemoteAddress();
                return a == null || a.getAddress() == null ? "" : a.getAddress().getHostAddress();
            }, null);
        }

        /** Behind {@code hops} trusted reverse proxies ({@link EidLogin#forwardedClientIp}). */
        public static ClientIp trustedProxies(int hops) {
            return new ClientIp(null, EidLogin.forwardedClientIp(hops));
        }

        /** No client IP — no per-IP start limit (the push limit stays). */
        public static ClientIp none() {
            return new ClientIp(null, null);
        }
    }

    public EidLoginHttpHandler(EidLogin login, ClientIp clientIp) {
        this.login = Objects.requireNonNull(login, "login");
        this.clientIp = Objects.requireNonNull(clientIp, "clientIp");
    }

    @Override
    public void handle(HttpExchange x) throws IOException {
        try {
            byte[] body;
            try (InputStream in = x.getRequestBody()) {
                body = in.readNBytes(EidLogin.MAX_START_BODY + 1);
                // Drain a little more so the client sees the answer instead of a reset; larger bodies just close.
                in.readNBytes(DRAIN_BYTES);
            }
            String url = x.getRequestURI().getRawPath() + (x.getRequestURI().getRawQuery() == null ? "" : "?" + x.getRequestURI().getRawQuery());
            Map<String, List<String>> headers = x.getRequestHeaders();
            EidLoginRequest r = new EidLoginRequest(x.getRequestMethod(), url, headers, body, null);
            String ip = clientIp.socket != null ? clientIp.socket.apply(x) : clientIp.headers != null ? clientIp.headers.apply(r) : null;
            if (ip != null && !ip.isEmpty()) r = new EidLoginRequest(r.method(), r.url(), r.headers(), r.rawBody(), ip);
            EidLoginResponse res = login.handle(r);
            for (Map.Entry<String, List<String>> e : res.headers().entrySet()) {
                for (String v : e.getValue()) x.getResponseHeaders().add(e.getKey(), v);
            }
            byte[] out = res.body().getBytes(StandardCharsets.UTF_8);
            x.sendResponseHeaders(res.status(), out.length == 0 ? -1 : out.length);
            if (out.length > 0) {
                try (OutputStream os = x.getResponseBody()) {
                    os.write(out);
                }
            }
        } finally {
            x.close();
        }
    }
}
