package mn.eidmongolia.eid;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Signing — the citizen signs a document digest with PIN2 (non-repudiation); also certificate choice
 * ({@link EidClient#sign()}, Go {@code SignService} + {@code certchoice.go}, TS {@code SignApi}). The response is
 * checked by the validator against the returned {@link SignContext} (store it with the session).
 *
 * <p>Certificate known before signing (client-side PAdES / CMS):
 *
 * <pre>{@code
 * NotificationSession cc = eid.sign().certificateChoiceByEtsi(etsi, null);   // or certificateChoiceDeviceLink (QR)
 * SessionResult r = eid.session().waitForResult(cc.sessionId(), WaitOptions.builder().expiresAt(cc.expiresAt()).build());
 * // validator: certificate choice → certificate + documentNumber; build the DTBS with that certificate
 * NotificationSession s = eid.sign().digestForSigner(new SignerRef(documentNumber, cc.sessionId()), dtbsB64, ix, null);
 * }</pre>
 *
 * <p>All calls are blocking; {@link Thread#interrupt()} cancels a call in flight.
 */
public final class SignService {
    private static final Pattern STD_B64 = Pattern.compile("(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?");

    private final RpHttp http;
    private final Credentials creds;
    private final CertificateLevel level;
    private final Duration ttl;
    private final Clock clock;

    SignService(RpHttp http, Credentials creds, CertificateLevel level, Duration ttl, Clock clock) {
        this.http = http;
        this.creds = creds;
        this.level = level;
        this.ttl = ttl;
        this.clock = clock;
    }

    /** A request body and the stored context built from the same values. */
    private record Req(Map<String, Object> body, SignContext sign) {
    }

    /** The v3 nested body + the RP's SignContext, from the same values (Go sign.go {@code body}). */
    private Req body(String digestB64, List<Interaction> interactions, SignOptions o, SignatureAlgorithm defAlg) {
        if (o == null) o = SignOptions.DEFAULTS;
        String ib64 = EidCrypto.interactionsToBase64(interactions);
        SignContext sc = new SignContext(digestB64, o.hashAlgorithm == null ? HashAlgorithm.SHA_256 : o.hashAlgorithm,
            o.signatureAlgorithm == null ? defAlg : o.signatureAlgorithm, creds.rpName(), ib64, o.callbackUrl);

        Map<String, Object> hash = new LinkedHashMap<>();
        hash.put("hashAlgorithm", sc.hashAlgorithm().wireName());
        Map<String, Object> spp = new LinkedHashMap<>();
        spp.put("digest", digestB64);
        spp.put("signatureAlgorithm", sc.signatureAlgorithm().wireName());
        spp.put("signatureAlgorithmParameters", hash);
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("relyingPartyUUID", creds.rpUuid());
        b.put("relyingPartyName", sc.relyingPartyName());
        b.put("certificateLevel", (o.certificateLevel == null ? level : o.certificateLevel).name());
        b.put("signatureProtocol", "RAW_DIGEST_SIGNATURE");
        b.put("signatureProtocolParameters", spp);
        b.put("interactions", ib64);
        if (!sc.initialCallbackUrl().isEmpty()) b.put("initialCallbackUrl", sc.initialCallbackUrl());
        if (!o.onBehalfOf.isEmpty()) b.put("onBehalfOf", o.onBehalfOf);
        if (!o.fileName.isEmpty()) b.put("fileName", o.fileName);
        return new Req(b, sc);
    }

    private NotificationSession notification(String path, Map<String, Object> body, SignContext sc) {
        Instant sent = clock.instant();
        StartResponse r = StartResponse.of(http.postJson(path, body, null), "POST " + EidException.maskPath(path));
        // A signature flow has no rpChallenge — the signature is checked against the digest.
        return new NotificationSession(r.sessionId, r.vc, "", null, sc, r.expiresAt(sent, ttl));
    }

    private DeviceLinkSession deviceLink(String path, Map<String, Object> body, SignContext sc) {
        Instant sent = clock.instant();
        StartResponse r = StartResponse.of(http.postJson(path, body, null), "POST " + EidException.maskPath(path));
        return new DeviceLinkSession(r.sessionId, r.sessionToken, r.sessionSecret, r.deviceLinkBase, r.vc, "", null,
            clock.instant(), DeviceLinkSessionType.SIGN, sc, "", "", r.expiresAt(sent, ttl));
    }

    /**
     * Push sign of a ready digest (standard base64) by national ID / civil ID / ETSI. Hash the document bytes yourself
     * ({@link EidCrypto#sha256Base64}).
     *
     * <p>(!) For a citizen with several phones the CA resolves the ETSI to the FIRST active device — the signature is
     * made with that phone's certificate. When the certificate must be known in advance (PAdES / CMS) use
     * {@link #certificateChoiceByEtsi} → {@link #digestForSigner}.
     *
     * @param options null = defaults
     */
    public NotificationSession digestByEtsi(String id, String digestB64, List<Interaction> interactions, SignOptions options) {
        Req q = body(digestB64, interactions, options, SignatureAlgorithm.RSASSA_PSS);
        return notification(Routes.SIGN_NOTIFICATION_ETSI.expand(id), q.body, q.sign);
    }

    /** Push sign of a ready digest by document number (from auth / certificate choice — a specific device). */
    public NotificationSession digestByDocument(String documentNumber, String digestB64, List<Interaction> interactions,
        SignOptions options) {
        Req q = body(digestB64, interactions, options, SignatureAlgorithm.RSASSA_PSS);
        return notification(Routes.SIGN_NOTIFICATION_DOCUMENT.expand(documentNumber), q.body, q.sign);
    }

    /** Push sign of a short text: its SHA-256 digest (UTF-8) is computed here. */
    public NotificationSession textByEtsi(String id, String text, List<Interaction> interactions, SignOptions options) {
        return digestByEtsi(id, EidCrypto.sha256Base64(EidCrypto.utf8(text)), interactions, options);
    }

    /**
     * QR / Web2App / App2App sign for a known citizen. Build the link with {@link DeviceLinkSession#linkInput} →
     * {@link DeviceLink#build}; Web2App/App2App need {@link SignOptions.Builder#callbackUrl}. Validate with the expected
     * flow = the link type shown.
     */
    public DeviceLinkSession deviceLinkByEtsi(String id, String digestB64, List<Interaction> interactions, SignOptions options) {
        Req q = body(digestB64, interactions, options, SignatureAlgorithm.RSASSA_PSS);
        return deviceLink(Routes.SIGN_DEVICE_LINK_ETSI.expand(id), q.body, q.sign);
    }

    /** QR / Web2App / App2App sign by document number (a specific device). */
    public DeviceLinkSession deviceLinkByDocument(String documentNumber, String digestB64, List<Interaction> interactions,
        SignOptions options) {
        Req q = body(digestB64, interactions, options, SignatureAlgorithm.RSASSA_PSS);
        return deviceLink(Routes.SIGN_DEVICE_LINK_DOCUMENT.expand(documentNumber), q.body, q.sign);
    }

    // ── Certificate known before signing (client-side PAdES / CMS) ──

    /**
     * The body for the chosen signer: PAdES defaults (sha256WithRSAEncryption, SHA-256); the digest length is checked
     * against the hash BEFORE the session starts (Go sign.go {@code signerBody}).
     */
    private Req signerBody(SignerRef signer, String digestB64, List<Interaction> interactions, SignOptions o) {
        if (signer == null || signer.documentNumber() == null || signer.documentNumber().isBlank()) {
            throw new IllegalArgumentException("eid: SignerRef.documentNumber хоосон — certificate choice-ийн үр дүнг өг");
        }
        Req q = body(digestB64, interactions, o, SignatureAlgorithm.SHA256_WITH_RSA);
        int want = EidCrypto.digest(q.sign.hashAlgorithm().jcaName(), new byte[0]).length;
        byte[] d = null;
        if (digestB64 != null && STD_B64.matcher(digestB64).matches()) {
            try {
                d = Base64.getDecoder().decode(digestB64);
            } catch (IllegalArgumentException e) {
                d = null;
            }
        }
        if (d == null || d.length != want) {
            throw new IllegalArgumentException("eid: digest нь стандарт base64, " + q.sign.hashAlgorithm().wireName()
                + "-ийн урт (" + want + " байт) байх ёстой");
        }
        return q;
    }

    /**
     * Push sign on EXACTLY the device chosen by certificate choice ({@link SignerRef#documentNumber()}). Started by ETSI
     * a citizen with several phones could sign on another phone (another certificate), breaking a CMS that embeds the
     * certificate (PAdES signingCertificateV2) — so the digest is ALWAYS signed by documentNumber.
     *
     * <p>With {@link SignerRef#certChoiceSessionId()}: /signature/notification/linked/{documentNumber} (linkedSessionID =
     * the certificate choice), else /signature/notification/document/{documentNumber}. Defaults: sha256WithRSAEncryption,
     * SHA-256 (digest = 32-byte DTBS).
     *
     * @throws IllegalArgumentException empty documentNumber, or a digest that is not standard base64 of the hash length
     *     (no request is sent)
     */
    public NotificationSession digestForSigner(SignerRef signer, String digestB64, List<Interaction> interactions,
        SignOptions options) {
        Req q = signerBody(signer, digestB64, interactions, options);
        String path = Routes.SIGN_NOTIFICATION_DOCUMENT.expand(signer.documentNumber());
        String linked = signer.certChoiceSessionId() == null ? "" : signer.certChoiceSessionId().strip();
        if (!linked.isEmpty()) {
            path = Routes.SIGN_NOTIFICATION_LINKED.expand(signer.documentNumber());
            q.body.put("linkedSessionID", linked);
        }
        return notification(path, q.body, q.sign);
    }

    /** The QR / Web2App / App2App variant of {@link #digestForSigner}: /signature/device-link/document/{documentNumber}. */
    public DeviceLinkSession deviceLinkForSigner(SignerRef signer, String digestB64, List<Interaction> interactions,
        SignOptions options) {
        Req q = signerBody(signer, digestB64, interactions, options);
        return deviceLink(Routes.SIGN_DEVICE_LINK_DOCUMENT.expand(signer.documentNumber()), q.body, q.sign);
    }

    // ── Certificate choice (Smart-ID v3; Go certchoice.go) ──

    /** CA dto.CertificateChoiceRequest — the CA rejects unknown fields (no interactions; callback only for device link). */
    private Map<String, Object> certChoiceBody(CertChoiceOptions o, boolean withCallback) {
        if (o == null) o = CertChoiceOptions.DEFAULTS;
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("relyingPartyUUID", creds.rpUuid());
        b.put("relyingPartyName", creds.rpName());
        b.put("certificateLevel", (o.certificateLevel == null ? level : o.certificateLevel).name());
        if (withCallback && !o.callbackUrl.isEmpty()) b.put("initialCallbackUrl", o.callbackUrl);
        return b;
    }

    /**
     * Push: asks the citizen's phone (national ID / civil ID / ETSI) to choose the signing certificate (no PIN). Then
     * {@link SessionService#waitForResult} → the validator's certificate-choice check. Needs the CERT permission.
     *
     * @param options null = defaults; {@link CertChoiceOptions.Builder#callbackUrl} is NOT sent here
     */
    public NotificationSession certificateChoiceByEtsi(String id, CertChoiceOptions options) {
        Instant sent = clock.instant();
        String path = Routes.CERT_CHOICE_ETSI.expand(id);
        StartResponse r = StartResponse.of(http.postJson(path, certChoiceBody(options, false), null),
            "POST " + EidException.maskPath(path));
        return new NotificationSession(r.sessionId, r.vc, "", null, null, r.expiresAt(sent, ttl));
    }

    /**
     * Device link: certificate choice when the citizen is not known in advance. QR ({@code linkInput(QR, …)}); with
     * {@link CertChoiceOptions.Builder#callbackUrl} also Web2App/App2App (the return path of a same-device linked
     * signature). Needs the CERT permission.
     */
    public DeviceLinkSession certificateChoiceDeviceLink(CertChoiceOptions options) {
        Instant sent = clock.instant();
        Map<String, Object> body = certChoiceBody(options, true);
        String path = Routes.CERT_CHOICE_DEVICE_LINK.expand();
        StartResponse r = StartResponse.of(http.postJson(path, body, null), "POST " + path);
        String callback = body.containsKey("initialCallbackUrl") ? (String) body.get("initialCallbackUrl") : "";
        return new DeviceLinkSession(r.sessionId, r.sessionToken, r.sessionSecret, r.deviceLinkBase, r.vc, "", null,
            clock.instant(), DeviceLinkSessionType.CERT, null, creds.rpName(), callback, r.expiresAt(sent, ttl));
    }
}
