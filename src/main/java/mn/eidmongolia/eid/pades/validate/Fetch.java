package mn.eidmongolia.eid.pades.validate;

import java.io.IOException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import mn.eidmongolia.eid.pades.EidPadesTransport;

/**
 * TS src/pades/fetch.ts Fetcher (server side: no https upgrade): national CRLs via the eID mirror, http/https only, a
 * 4 MiB response cap, GET responses cached for one validation. The transport is the SDK's pluggable
 * {@link EidPadesTransport}.
 */
final class Fetch {
    static final int MAX_RESPONSE = 4 << 20;
    private static final Map<String, String> CRL_MIRROR = Map.of(
        "http://esign.gov.mn/MNICA-2022.crl", "https://crl.eidmongolia.mn/MNICA-2022.crl",
        "http://esign.gov.mn/MNRCA-2021.crl", "https://crl.eidmongolia.mn/MNRCA-2021.crl");

    private final EidPadesTransport transport;
    private final Map<String, byte[]> cache = new HashMap<>();

    Fetch(EidPadesTransport transport) {
        this.transport = transport;
    }

    private static String target(String raw) throws IOException {
        String m = CRL_MIRROR.get(raw);
        if (m != null) return m;
        int i = raw.indexOf(':');
        String scheme = i < 0 ? "" : raw.substring(0, i).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) throw new IOException("URL scheme not supported");
        return raw;
    }

    byte[] send(String method, String raw, String contentType, byte[] body) throws IOException {
        String url = target(raw);
        if (method.equals("GET")) {
            byte[] hit = cache.get(url);
            if (hit != null) return hit;
        }
        byte[] out = transport.send(method, url, contentType, body);
        if (out == null || out.length > MAX_RESPONSE) throw new IOException("no or oversized response");
        if (method.equals("GET")) cache.put(url, out);
        return out;
    }
}
