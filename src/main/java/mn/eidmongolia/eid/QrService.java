package mn.eidmongolia.eid;

import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import mn.eidmongolia.eid.pades.EidQr;
import mn.eidmongolia.eid.pades.EidQrException;

/**
 * «My QR» over the RP-API ({@link EidClient#qr()}, Go {@code QRService}, .NET {@code EidQrClient}): {@link #parse} →
 * {@link #start} → {@link #result} / {@link #check}. Verification is {@link EidQr#verify} (the hardened contract §6.1
 * checks) with {@link EidClient.Builder#qrTrust} — default: the embedded national root, issuer 04, OCSP hard-fail (OCSP
 * «unknown» = revoked, 48 h). Thread-safe.
 *
 * <p>Errors: {@link EidQrException} ({@link EidQrException#FORMAT_INVALID} client side, {@link EidQrException#TOKEN_INVALID}
 * / {@link EidQrException#PRESENTATION_GONE} with the RP-API error as the cause, {@link EidQrException#PENDING}, and every
 * verification code — then do NOT trust the presentation); {@link EidException.SessionFailed} (the citizen refused / CA
 * TIMEOUT); other RP-API errors unchanged (403 {@link EidException.Forbidden}, 409
 * {@link EidException.NoSigningCertificate}, 429).
 */
public final class QrService {
    private final RpHttp http;
    private final Credentials creds;
    private final SessionService session;
    private final Clock clock;
    private final String issuer;
    private final EidQr.Trust trust;

    QrService(RpHttp http, Credentials creds, SessionService session, Clock clock, String issuer, EidQr.Trust trust) {
        this.http = http;
        this.creds = creds;
        this.session = session;
        this.clock = clock;
        this.issuer = issuer == null || issuer.isEmpty() ? EidQr.DEFAULT_ISSUER : issuer;
        this.trust = trust == null ? EidQr.Trust.DEFAULT : trust;
    }

    /** {@link EidQr#parse}. */
    public EidQr.Parsed parse(String scanned) {
        return EidQr.parse(scanned);
    }

    /**
     * POST /authentication/qr: hands the (single-use) QR token to the CA, which sends a PIN2 request to the citizen's
     * phone (no VC — the phone shows one sentence). A malformed QR → {@link EidQrException#FORMAT_INVALID} without any
     * request.
     */
    public QrSession start(QrStartRequest req) {
        if (req == null) throw new IllegalArgumentException("eid: QR.Start: QrStartRequest шаардлагатай");
        EidQr.Parsed p = EidQr.parse(req.qr());
        String nonce = req.nonce() == null || req.nonce().isEmpty() ? nonce() : req.nonce();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("qr", EidQr.PREFIX + p.token());
        body.put("relyingPartyUUID", creds.rpUuid());
        body.put("relyingPartyName", req.relyingPartyName() == null || req.relyingPartyName().isEmpty() ? creds.rpName() : req.relyingPartyName());
        body.put("nonce", nonce);
        Json.Obj r;
        try {
            r = http.postJson(Routes.AUTH_QR.expand(), body, null).obj("POST /authentication/qr");
        } catch (EidException.Api e) {
            throw serverErr(e);
        }
        String sid = r.optString("sessionID");
        if (sid.isEmpty()) throw new EidException("eid: POST /authentication/qr: sessionID алга");
        return new QrSession(sid, nonce);
    }

    /** base64url(16 CSPRNG bytes), 22 characters (Go {@code qrNonce}). */
    private static String nonce() {
        byte[] b = new byte[16];
        EidCrypto.RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    /**
     * The CA's QR codes become {@link EidQrException} with the RP-API error as the cause (Go {@code qrServerErr}): 410 →
     * PRESENTATION_GONE (whatever the body's code), QR_TOKEN_INVALID; others unchanged.
     */
    private static RuntimeException serverErr(EidException.Api e) {
        if (e.status() == 410) {
            return new EidQrException(EidQrException.PRESENTATION_GONE, "presentation аль хэдийн уншигдсан эсвэл хугацаа дууссан — шинэ QR уншуулна уу", e);
        }
        if (EidQrException.TOKEN_INVALID.equals(e.code())) return new EidQrException(e.code(), "CA " + e.status(), e);
        return e;
    }

    /**
     * Long-polls GET /session/{id} until it ends (o null → the discovery session TTL) and verifies the presentation
     * ({@link #verify}). Refused / CA TIMEOUT → {@link EidException.SessionFailed}; still RUNNING when the wait ends →
     * {@link EidQrException#PENDING}; 410 → {@link EidQrException#PRESENTATION_GONE} (a presentation is read once).
     */
    public EidQr.Result result(QrSession s, WaitOptions o) {
        if (s == null || s.sessionId() == null || s.sessionId().isEmpty()) throw new IllegalArgumentException("eid: QR.Result: QrSession шаардлагатай");
        SessionResult r;
        try {
            r = session.waitForResult(s.sessionId(), o);
        } catch (EidException.Api e) {
            throw serverErr(e);
        }
        if (!SessionResult.STATE_COMPLETE.equals(r.state())) throw new EidQrException(EidQrException.PENDING, "иргэн хараахан хариулаагүй", null);
        return finish(r, s);
    }

    /**
     * One check for a polling UI: GET /session/{id} (up to serverPoll; null / ≤ 0 = 1 s). Not answered yet →
     * {@code QrCheck(false, null)}; otherwise as {@link #result}.
     */
    public QrCheck check(QrSession s, Duration serverPoll) {
        if (s == null || s.sessionId() == null || s.sessionId().isEmpty()) throw new IllegalArgumentException("eid: QR.Check: QrSession шаардлагатай");
        Duration p = serverPoll == null || serverPoll.isZero() || serverPoll.isNegative() ? Duration.ofSeconds(1) : serverPoll;
        SessionResult r;
        try {
            r = session.poll(s.sessionId(), p);
        } catch (EidException.Api e) {
            throw serverErr(e);
        }
        if (!SessionResult.STATE_COMPLETE.equals(r.state())) return new QrCheck(false, null);
        return new QrCheck(true, finish(r, s));
    }

    private EidQr.Result finish(SessionResult r, QrSession s) {
        if (!SessionResult.END_RESULT_OK.equals(r.endResult())) {
            throw new EidException.SessionFailed(r.endResult() == null || r.endResult().isEmpty() ? "UNKNOWN" : r.endResult());
        }
        if (r.presentationJws() == null || r.presentationJws().isEmpty()) {
            throw new EidQrException(EidQrException.JWS_MALFORMED, "хариунд presentation алга", null);
        }
        return verify(r.presentationJws(), s);
    }

    /** Verifies a stored presentation JWS against the session ({@link EidClient.Builder#qrTrust}, {@link EidClient.Builder#qrIssuer}). */
    public EidQr.Result verify(String jws, QrSession s) {
        if (s == null) throw new IllegalArgumentException("eid: QR.Verify: QrSession шаардлагатай");
        return EidQr.verify(jws, new EidQr.Expect(creds.rpUuid(), s.sessionId(), s.nonce(), issuer, clock.instant()), trust);
    }
}
