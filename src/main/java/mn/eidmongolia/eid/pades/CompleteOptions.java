package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * {@link EidPades#complete} input. Immutable; {@link #DEFAULT} or {@link #builder()}.
 *
 * <ul>
 *   <li>{@code tsaUrl} — RFC 3161 TSA; null → {@code https://tsa.timeserver.mn/}</li>
 *   <li>{@code roots} — trust anchors DER (TSA chain); empty → Mongolian National Root CA (other values: sandbox/tests)</li>
 *   <li>{@code transport} — HTTP for TSA / OCSP / CRL; null → HttpURLConnection, 10 s total deadline per request, no
 *       redirects, ≤ 4 MiB</li>
 * </ul>
 */
public final class CompleteOptions {
    public static final CompleteOptions DEFAULT = builder().build();

    private final String tsaUrl;
    private final List<byte[]> roots;
    private final EidPadesTransport transport;

    private CompleteOptions(Builder b) {
        tsaUrl = b.tsaUrl;
        List<byte[]> r = new ArrayList<>();
        for (byte[] d : b.roots) r.add(d.clone());
        roots = Collections.unmodifiableList(r);
        transport = b.transport;
    }

    public static Builder builder() {
        return new Builder();
    }

    public String tsaUrl() {
        return tsaUrl;
    }

    public List<byte[]> roots() {
        return roots;
    }

    public EidPadesTransport transport() {
        return transport;
    }

    public static final class Builder {
        private String tsaUrl;
        private List<byte[]> roots = Collections.emptyList();
        private EidPadesTransport transport;

        private Builder() {
        }

        public Builder tsaUrl(String v) {
            tsaUrl = v;
            return this;
        }

        public Builder roots(List<byte[]> v) {
            roots = v == null ? Collections.emptyList() : new ArrayList<>(v);
            return this;
        }

        public Builder transport(EidPadesTransport v) {
            transport = v;
            return this;
        }

        public CompleteOptions build() {
            return new CompleteOptions(this);
        }
    }
}
