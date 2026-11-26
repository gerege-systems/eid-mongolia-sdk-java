package mn.eidmongolia.eid;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Authentication — signs the citizen in (PIN1; {@link EidClient#auth()}, Go {@code AuthService}, TS {@code AuthApi}).
 * Every start creates a random rpChallenge; the response's ACSP_V2 signature is checked by the validator against the
 * returned {@link AcspContext} (store it with the session on the RP backend).
 *
 * <p>All calls are blocking; {@link Thread#interrupt()} cancels a call in flight ({@link EidException.Network#cancelled()}).
 */
public final class AuthService {
    private final RpHttp http;
    private final Credentials creds;
    private final CertificateLevel level;
    private final Clock clock;

    AuthService(RpHttp http, Credentials creds, CertificateLevel level, Clock clock) {
        this.http = http;
        this.creds = creds;
        this.level = level;
        this.clock = clock;
    }

    /** A request body and the validator context built from the same values. */
    private record Req(Map<String, Object> body, AcspContext acsp) {
    }

    /** The v3 nested body + the validator context, from the same values (Go auth.go {@code body}). */
    private Req body(List<Interaction> interactions, FlowType flow, AuthOptions o) {
        if (o == null) o = AuthOptions.DEFAULTS;
        String challenge = EidCrypto.randomChallenge(64);
        String ib64 = EidCrypto.interactionsToBase64(interactions);
        String callback = o.callbackUrl;
        List<FlowType> flows = new ArrayList<>(List.of(flow));
        if (!callback.isEmpty()) {
            flows.add(FlowType.APP2APP);
            flows.add(FlowType.WEB2APP);
        }
        AcspContext acsp = new AcspContext(challenge, creds.rpName(), "", ib64, callback, flows,
            o.signatureAlgorithm == null ? SignatureAlgorithm.RSASSA_PSS : o.signatureAlgorithm,
            o.hashAlgorithm == null ? HashAlgorithm.SHA_512 : o.hashAlgorithm);

        Map<String, Object> hash = new LinkedHashMap<>();
        hash.put("hashAlgorithm", acsp.hashAlgorithm().wireName());
        Map<String, Object> spp = new LinkedHashMap<>();
        spp.put("rpChallenge", challenge);
        spp.put("signatureAlgorithm", acsp.signatureAlgorithm().wireName());
        spp.put("signatureAlgorithmParameters", hash);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("relyingPartyUUID", creds.rpUuid());
        b.put("relyingPartyName", acsp.relyingPartyName());
        b.put("certificateLevel", (o.certificateLevel == null ? level : o.certificateLevel).name());
        b.put("signatureProtocol", "ACSP_V2");
        b.put("signatureProtocolParameters", spp);
        b.put("interactions", ib64);
        if (!callback.isEmpty()) b.put("initialCallbackUrl", callback);
        if (!o.onBehalfOf.isEmpty()) b.put("onBehalfOf", o.onBehalfOf);
        return new Req(b, acsp);
    }

    private NotificationSession notification(String path, List<Interaction> interactions, AuthOptions o) {
        Req req = body(interactions, FlowType.NOTIFICATION, o);
        AcspContext acsp = req.acsp;
        StartResponse r = StartResponse.of(http.postJson(path, req.body, null), "POST " + EidException.maskPath(path));
        return new NotificationSession(r.sessionId, r.vc, acsp.rpChallenge(), acsp, null, r.caExpiresAt);
    }

    private DeviceLinkSession deviceLink(String path, List<Interaction> interactions, AuthOptions o) {
        Req req = body(interactions, FlowType.QR, o);
        AcspContext acsp = req.acsp;
        StartResponse r = StartResponse.of(http.postJson(path, req.body, null), "POST " + EidException.maskPath(path));
        return new DeviceLinkSession(r.sessionId, r.sessionToken, r.sessionSecret, r.deviceLinkBase, r.vc,
            acsp.rpChallenge(), acsp, clock.instant(), DeviceLinkSessionType.AUTH, null, "", "", r.caExpiresAt);
    }

    /**
     * Push by national ID / civil ID / ETSI (PNOMN-…; the server recognises the kind): a notification goes to the
     * citizen's phone. Validate with expected flow {@link FlowType#NOTIFICATION}.
     *
     * @param options null = defaults
     */
    public NotificationSession notificationByEtsi(String id, List<Interaction> interactions, AuthOptions options) {
        return notification(Routes.AUTH_NOTIFICATION_ETSI.expand(id), interactions, options);
    }

    /** Push by document number (a specific device). */
    public NotificationSession notificationByDocument(String documentNumber, List<Interaction> interactions, AuthOptions options) {
        return notification(Routes.AUTH_NOTIFICATION_DOCUMENT.expand(documentNumber), interactions, options);
    }

    /**
     * QR / Web2App / App2App when the citizen is not known in advance. Build the link with
     * {@link DeviceLinkSession#linkInput} → {@link DeviceLink#build} (QR: every second, or {@link DeviceLink#tickQr}).
     */
    public DeviceLinkSession deviceLinkAnonymous(List<Interaction> interactions, AuthOptions options) {
        return deviceLink(Routes.AUTH_DEVICE_LINK_ANONYMOUS.expand(), interactions, options);
    }

    /** QR / Web2App / App2App for a known citizen (national ID / civil ID / ETSI). */
    public DeviceLinkSession deviceLinkByEtsi(String id, List<Interaction> interactions, AuthOptions options) {
        return deviceLink(Routes.AUTH_DEVICE_LINK_ETSI.expand(id), interactions, options);
    }

    /**
     * Discovery {@code sessionTtl} ({@code {"auth": s, "sign": s}}) — the CA's live session lifetimes. Absent fields
     * (older CA) → {@link Duration#ZERO}. Blocking; an interrupt cancels it ({@link EidException.Network#cancelled()}).
     */
    public SessionTtl sessionTtl() {
        return fetchSessionTtl(http, null);
    }

    /**
     * {@link #sessionTtl()} with its own deadline instead of the client's per-call timeout (the login backend uses 2 s,
     * as Go does). null / ≤ 0 = the client's timeout.
     */
    public SessionTtl sessionTtl(Duration timeout) {
        return fetchSessionTtl(http, timeout);
    }

    static SessionTtl fetchSessionTtl(RpHttp http, Duration timeout) {
        Json.Obj d = http.getJson(Routes.DISCOVERY_PATH, timeout).obj("GET " + Routes.DISCOVERY_PATH);
        Json.Obj t = d.optObj("sessionTtl");
        if (t == null) return new SessionTtl(Duration.ZERO, Duration.ZERO);
        long a = t.optLong("auth", 0);
        long s = t.optLong("sign", 0);
        return new SessionTtl(a > 0 ? Duration.ofSeconds(a) : Duration.ZERO, s > 0 ? Duration.ofSeconds(s) : Duration.ZERO);
    }
}
