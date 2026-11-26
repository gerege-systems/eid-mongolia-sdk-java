package mn.eidmongolia.eid;

import java.io.IOException;

/**
 * HTTP for the RP-API client — injectable (mTLS, proxy, tests), modelled on
 * {@link mn.eidmongolia.eid.pades.EidPadesTransport}. The default is {@link JdkHttpTransport} over
 * {@link java.net.http.HttpClient}; for mTLS pass {@code JdkHttpTransport.create(sslContext)}.
 *
 * <p>Contract: return the response for EVERY status (the client maps non-2xx to {@link EidException}); never follow
 * redirects with the Authorization header; read at most {@link EidHttpRequest#maxResponseBytes()} + 1 body bytes
 * (returning more than the limit signals an oversized body); finish within {@link EidHttpRequest#timeout()} (whole
 * exchange, body included) or throw {@link java.net.http.HttpTimeoutException} / {@link java.net.SocketTimeoutException};
 * on {@link Thread#interrupt()} abort and throw {@link java.io.InterruptedIOException} (the client keeps the interrupt
 * flag set). Other I/O failures: any {@link IOException}.
 */
@FunctionalInterface
public interface EidTransport {
    EidHttpResponse send(EidHttpRequest request) throws IOException;
}
