package mn.eidmongolia.eid.pades;

import java.io.IOException;

/**
 * HTTP for TSA / OCSP / CRL ({@link EidPades#complete}). Injectable (sandbox, proxy, tests) — Go
 * {@code CompleteOptions.HTTPClient}. Must return the body of a 200 response and throw otherwise.
 */
@FunctionalInterface
public interface EidPadesTransport {
    /**
     * @param method "GET" or "POST"
     * @param contentType request Content-Type (POST only), else null
     * @param body request body (POST only), else null
     * @return the response body of a 200 response
     */
    byte[] send(String method, String url, String contentType, byte[] body) throws IOException;
}
