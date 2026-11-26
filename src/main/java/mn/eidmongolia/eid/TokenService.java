package mn.eidmongolia.eid;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;

/**
 * The citizen's USB token (PKCS#11, EC P-256) — {@link EidClient#token()}, Go {@code TokenService}, TS {@code TokenApi}:
 *
 * <ul>
 *   <li>certificate issuance (CA docs/TOKEN_CERT.md, RP permission TOKEN_ISSUE): {@link #issueCertificate} → the citizen
 *       approves with PIN2 → {@link SessionService#poll} (tokenCertificate.status ISSUED) → {@link #certificateResult} →
 *       {@link #verifyTokenCertificates};
 *   <li>sign-in with the token (docs/TOKEN_AUTH.md, AUTH): {@link #authChallenge} → the token signs
 *       {@link #tokenAuthDigest} with CKM_ECDSA (raw r‖s) → {@link #authVerify}.
 * </ul>
 *
 * Errors: {@link EidException.Api#code()} ∈ {@link EidErrorCodes#TOKEN} ({@link #tokenLimitOf} for TOKEN_LIMIT_REACHED);
 * temporary ones (RATE_LIMITED, STATE_UNAVAILABLE, ISSUANCE_PENDING) are {@link EidException.Api#retryable()}.
 */
public final class TokenService {
    /** {@link TokenCertInput#appTransaction()} limit (the CA's, 16 KiB). */
    public static final int MAX_APP_TRANSACTION_BYTES = 16 << 10;
    public static final String KIND_PERSONAL = "PERSONAL";
    public static final String KIND_ORGANIZATION = "ORGANIZATION";
    /** The CA waits ≤ 15 s for an unfinished issuance. */
    static final Duration RESULT_TIMEOUT = Duration.ofSeconds(30);
    private static final Pattern RP_UUID = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    private static final byte[] AUTH_TAG = "eID-TOKEN-AUTH".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private final RpHttp http;
    private final Credentials creds;
    private final ResponseValidator validator;

    TokenService(RpHttp http, Credentials creds, ResponseValidator validator) {
        this.http = http;
        this.creds = creds;
        this.validator = validator;
    }

    private static EidException.Validation invalid(String reason, String detail) {
        return new EidException.Validation(reason, detail);
    }

    /**
     * POST /token/certificate: starts the token's AUTH + SIGN issuance (the citizen approves on the phone). The CA's CSR
     * hashes must equal the CSRs sent, else {@link EidException.Validation} {@link ValidationReasons#TOKEN_RESPONSE}.
     * Renewal on the same tokenSerial keeps the scope (else 409 TOKEN_SCOPE_CHANGE). Other 409s: TOKEN_LIMIT_REACHED
     * ({@link #tokenLimitOf}), TOKEN_IN_USE, ACCOUNT_DELETE_PENDING, TOKEN_ISSUANCE_PENDING, NO_ACTIVE_DEVICE,
     * KYC_INCOMPLETE, CSR_KEY_REUSED; 400 APP_ATTESTATION_INVALID; 403 without TOKEN_ISSUE.
     *
     * @throws IllegalArgumentException signerEtsi / CSRs / tokenSerial missing, or appTransaction over 16 KiB (nothing sent)
     */
    public TokenCertStart issueCertificate(TokenCertInput in) {
        Map<String, Object> req = certRequest(in);
        String op = "POST /token/certificate";
        Json.Obj r = http.postJson(Routes.TOKEN_CERTIFICATE.expand(), req, null).obj(op);
        String a = r.optString("csrAuthSha256");
        String s = r.optString("csrSignSha256");
        if (!hexSha256Equal(a, in.csrAuth()) || !hexSha256Equal(s, in.csrSign())) {
            throw invalid(ValidationReasons.TOKEN_RESPONSE, "token: CA-ийн csrAuthSha256/csrSignSha256 илгээсэн CSR-тэй таарсангүй");
        }
        return new TokenCertStart(r.optString("sessionID"), StartResponse.vcOf(r.get("vc")), a.toLowerCase(Locale.ROOT),
            s.toLowerCase(Locale.ROOT), r.optString("expiresAt"), supersedes(r));
    }

    /**
     * POST /token/certificate {"dryRun": true} (discovery tokenCertificate.dryRun): every check of
     * {@link #issueCertificate} with the same codes, but no session / push. Flow: CSR → preview → warn about
     * {@link TokenCertPreview#supersedes()} → {@link #issueCertificate} with the same input. An answer without
     * dryRun true → {@link EidException.Validation} {@link ValidationReasons#TOKEN_RESPONSE}.
     */
    public TokenCertPreview previewCertificate(TokenCertInput in) {
        Map<String, Object> req = certRequest(in);
        req.put("dryRun", true);
        Json.Obj r = http.postJson(Routes.TOKEN_CERTIFICATE.expand(), req, null).obj("POST /token/certificate");
        if (!r.optBool("dryRun", false)) throw invalid(ValidationReasons.TOKEN_RESPONSE, "token: dryRun хариу биш (CA dryRun-ийг дэмжихгүй)");
        return new TokenCertPreview(supersedes(r));
    }

    private static List<TokenSupersede> supersedes(Json.Obj r) {
        List<TokenSupersede> out = new ArrayList<>();
        for (Json.Obj x : Dto.objects(r, "supersedes")) out.add(new TokenSupersede(x.optString("tokenSerial")));
        return Collections.unmodifiableList(out);
    }

    /** The request body (CA DisallowUnknownFields — exactly these members; Go {@code certRequest}). */
    private Map<String, Object> certRequest(TokenCertInput in) {
        if (in == null || blank(in.signerEtsi()) || in.csrAuth() == null || in.csrAuth().length == 0 || in.csrSign() == null
            || in.csrSign().length == 0 || blank(in.tokenSerial())) {
            throw new IllegalArgumentException("eid: token: SignerEtsi, CSRAuth, CSRSign, TokenSerial шаардлагатай");
        }
        String app = in.appTransaction() == null ? "" : in.appTransaction();
        if (EidCrypto.utf8(app).length > MAX_APP_TRANSACTION_BYTES) throw new IllegalArgumentException("eid: token: AppTransaction 16 KiB-аас их");
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("relyingPartyUUID", creds.rpUuid());
        b.put("relyingPartyName", creds.rpName());
        b.put("signer", Map.of("etsi", in.signerEtsi().strip()));
        b.put("csrAuth", Base64.getEncoder().encodeToString(in.csrAuth()));
        b.put("csrSign", Base64.getEncoder().encodeToString(in.csrSign()));
        b.put("tokenSerial", in.tokenSerial().strip());
        if (in.tokenLabel() != null && !in.tokenLabel().isEmpty()) b.put("tokenLabel", in.tokenLabel());
        b.put("onBehalfOf", in.onBehalfOf() == null ? "" : in.onBehalfOf().strip());
        b.put("flow", "notification");
        String appT = app.strip();
        if (!appT.isEmpty()) b.put("appTransaction", appT);
        return b;
    }

    private static boolean blank(String s) {
        return s == null || s.strip().isEmpty();
    }

    /**
     * GET /token/certificate/{sessionID}: the issued AUTH + SIGN certificates and chain (30 s — the CA waits up to 15 s
     * for an unfinished issuance). Conditions changed between start and approval → 409 (TOKEN_LIMIT_REACHED / TOKEN_IN_USE
     * / TOKEN_SCOPE_CHANGE / ACCOUNT_DELETE_PENDING); 410 RESULT_EXPIRED after 24 h.
     */
    public TokenCertResult certificateResult(String sessionId) {
        RpHttp.Result res = http.getJson(Routes.TOKEN_CERTIFICATE_RESULT.expand(sessionId), RESULT_TIMEOUT);
        Json.Obj r = res.obj("GET /token/certificate/…");
        return new TokenCertResult(r.optString("status"), TokenCertItem.of(r.optObj("auth")), TokenCertItem.of(r.optObj("sign")),
            Dto.strings(r, "chain"), r.optString("chainPem"), TokenOrganization.of(r.optObj("organization")), r.optString("keyMedium"),
            r.optString("certificateLevel"), Dto.raw(res));
    }

    /**
     * Each issued AUTH / SIGN certificate decodes and carries EXACTLY the CSR's public key (SubjectPublicKeyInfo bytes; Go
     * {@code VerifyTokenCertificates}). Otherwise {@link EidException.Validation} {@link ValidationReasons#TOKEN_CERTIFICATE}
     * — do not write the certificate to the token.
     *
     * @throws IllegalArgumentException a CSR that does not decode
     */
    public static void verifyTokenCertificates(TokenCertResult r, byte[] csrAuth, byte[] csrSign) {
        if (r == null || r.auth() == null || r.sign() == null) throw invalid(ValidationReasons.TOKEN_CERTIFICATE, "token: auth/sign гэрчилгээ алга");
        Object[][] parts = {{"auth", r.auth(), csrAuth}, {"sign", r.sign(), csrSign}};
        for (Object[] p : parts) {
            String name = (String) p[0];
            byte[] csrSpki = csrSpki((byte[]) p[2], name);
            byte[] der = SealService.b64(((TokenCertItem) p[1]).certificate());
            if (der == null) throw invalid(ValidationReasons.TOKEN_CERTIFICATE, "token: " + name + " гэрчилгээ base64 буруу");
            Cert c;
            try {
                c = Cert.parse(der);
            } catch (IllegalArgumentException e) {
                throw invalid(ValidationReasons.TOKEN_CERTIFICATE, "token: " + name + " гэрчилгээ задарсангүй");
            }
            if (!MessageDigest.isEqual(c.rawSubjectPublicKeyInfo, csrSpki)) {
                throw invalid(ValidationReasons.TOKEN_CERTIFICATE, "token: " + name + " гэрчилгээний түлхүүр CSR-ийнхтэй таарсангүй");
            }
        }
    }

    /**
     * The SubjectPublicKeyInfo element of a PKCS#10 CertificationRequest (Go {@code x509.ParseCertificateRequest}
     * {@code RawSubjectPublicKeyInfo}): SEQUENCE { SEQUENCE { version INTEGER, subject Name, spki, [0] attributes },
     * signatureAlgorithm, BIT STRING } — DER only, no trailing data.
     */
    static byte[] csrSpki(byte[] csr, String name) {
        try {
            if (csr == null || csr.length == 0) throw new IllegalArgumentException("empty");
            Der.Tlv t = Der.parse(csr);
            if (t.tag != Der.SEQUENCE || t.end != csr.length) throw new IllegalArgumentException("not a DER SEQUENCE");
            List<Der.Tlv> top = t.children();
            if (top.size() != 3 || top.get(0).tag != Der.SEQUENCE || top.get(1).tag != Der.SEQUENCE || top.get(2).tag != Der.BIT_STRING) {
                throw new IllegalArgumentException("not a CertificationRequest");
            }
            List<Der.Tlv> info = top.get(0).children();
            if (info.size() < 3 || info.get(0).tag != Der.INTEGER || info.get(1).tag != Der.SEQUENCE || info.get(2).tag != Der.SEQUENCE) {
                throw new IllegalArgumentException("not a CertificationRequestInfo");
            }
            Der.Tlv spki = info.get(2);
            // Go parses the key too: the SubjectPublicKeyInfo must decode as a key of its algorithm.
            String alg = spki.child(0).child(0).oid();
            String kf = "1.2.840.10045.2.1".equals(alg) ? "EC" : "1.2.840.113549.1.1.1".equals(alg) ? "RSA" : "1.3.101.112".equals(alg) ? "Ed25519" : null;
            if (kf == null) throw new IllegalArgumentException("unsupported key algorithm");
            java.security.KeyFactory.getInstance(kf).generatePublic(new java.security.spec.X509EncodedKeySpec(spki.encoded()));
            return spki.encoded();
        } catch (Exception e) {
            throw new IllegalArgumentException("eid: token: " + name + " CSR задарсангүй: " + e.getMessage(), e);
        }
    }

    /** POST /token/auth/challenge: a one-time challenge bound to this RP (2 min). */
    public TokenAuthChallenge authChallenge() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("relyingPartyUUID", creds.rpUuid());
        body.put("relyingPartyName", creds.rpName());
        String op = "POST /token/auth/challenge";
        Json.Obj r = http.postJson(Routes.TOKEN_AUTH_CHALLENGE.expand(), body, null).obj(op);
        return new TokenAuthChallenge(r.optString("challengeId"), r.optString("challenge"), r.optString("rpUUID"),
            Dto.instant(r, "expiresAt", op));
    }

    /**
     * POST /token/auth/verify: the token's AUTH certificate (DER) + raw r‖s (64 bytes) over the challenge (Go
     * {@code AuthVerify}). The SDK does not trust the CA's OK alone: BEFORE sending, ch.rpUuid must be this RP, the
     * signature must verify over {@link #tokenAuthDigest}(ch.rpUuid, ch.challenge) with the certificate's EC P-256 key, and
     * the certificate must pass the client's {@link TrustConfig} (subject, validity, purpose auth, chain, issuer allowlist)
     * — else {@link EidException.Validation} and nothing is sent; then the CA's endResult must be OK and identity.etsi the
     * certificate's SERIALNUMBER. Revocation is the CA's; call {@link ResponseValidator#checkRevocation} for your own.
     * A challenge is single-use — get a new one after an error.
     *
     * @throws IllegalArgumentException certificate does not parse, or challenge / signature missing
     */
    public TokenAuthResult authVerify(TokenAuthChallenge ch, byte[] certDer, byte[] signature) {
        Cert crt;
        try {
            crt = Cert.parse(certDer);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("eid: token auth: гэрчилгээ задарсангүй: " + e.getMessage(), e);
        }
        if (ch == null || ch.challengeId() == null || ch.challengeId().isEmpty() || signature == null || signature.length == 0) {
            throw new IllegalArgumentException("eid: token auth: challenge (ChallengeID, Challenge, RPUUID) ба signature шаардлагатай");
        }
        if (ch.rpUuid() == null || !ch.rpUuid().equalsIgnoreCase(creds.rpUuid())) {
            throw invalid(ValidationReasons.TOKEN_CHALLENGE, "token auth: challenge өөр RP-д холбогдсон (rpUUID)");
        }
        byte[] digest;
        try {
            digest = tokenAuthDigest(ch.rpUuid(), ch.challenge());
        } catch (IllegalArgumentException e) {
            throw new EidException.Validation(ValidationReasons.TOKEN_CHALLENGE, "token auth: challenge/rpUUID хэлбэр буруу", e);
        }
        if (!verifyTokenSignature(crt, digest, signature)) {
            throw invalid(ValidationReasons.TOKEN_SIGNATURE, "token auth: гарын үсэг challenge-тэй таарсангүй (EC P-256 r||s)");
        }
        validator.verifyTokenAuthCertificate(crt);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("challengeId", ch.challengeId());
        body.put("certificate", Base64.getEncoder().encodeToString(certDer));
        body.put("signature", Base64.getEncoder().encodeToString(signature));
        String op = "POST /token/auth/verify";
        RpHttp.Result res = http.postJson(Routes.TOKEN_AUTH_VERIFY.expand(), body, null);
        Json.Obj r = res.obj(op);
        if (!SessionResult.END_RESULT_OK.equals(Dto.obj(r, "result").optString("endResult"))) {
            throw invalid(ValidationReasons.TOKEN_RESULT, "token auth: endResult OK биш");
        }
        Json.Obj id = Dto.obj(r, "identity");
        String etsi = id.optString("etsi");
        String serial = crt.subjectAttr(Cert.OID_SERIAL_NUMBER);
        if (etsi.isEmpty() || !etsi.equals(serial)) {
            throw invalid(ValidationReasons.TOKEN_RESULT, "token auth: identity.etsi нь гэрчилгээний SERIALNUMBER биш");
        }
        Json.Obj cert = Dto.obj(r, "cert");
        return new TokenAuthResult(new TokenIdentity(etsi, id.optString("givenName"), id.optString("surname")), cert.optString("serialHex"),
            Dto.instant(cert, "notAfter", op), TokenOrganization.of(r.optObj("organization")), Dto.raw(res));
    }

    /** The token's raw r‖s (P-256, 64 bytes) over digest with the certificate's key (Go {@code verifyTokenSignature}). */
    static boolean verifyTokenSignature(Cert crt, byte[] digest, byte[] sig) {
        if (!crt.isEc() || !Prehashed.isP256(crt.publicKey()) || sig.length != 64) return false;
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 0, 32));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(sig, 32, 64));
        try {
            Signature v = Signature.getInstance("NONEwithECDSA");
            v.initVerify(crt.publicKey());
            v.update(digest);
            return v.verify(derSignature(r, s));
        } catch (Exception e) {
            return false;
        }
    }

    private static byte[] derSignature(BigInteger r, BigInteger s) {
        byte[] rb = r.toByteArray();
        byte[] sb = s.toByteArray();
        byte[] out = new byte[6 + rb.length + sb.length];
        out[0] = 0x30;
        out[1] = (byte) (4 + rb.length + sb.length);
        out[2] = 0x02;
        out[3] = (byte) rb.length;
        System.arraycopy(rb, 0, out, 4, rb.length);
        out[4 + rb.length] = 0x02;
        out[5 + rb.length] = (byte) sb.length;
        System.arraycopy(sb, 0, out, 6 + rb.length, sb.length);
        return out;
    }

    /**
     * The 32 bytes the token signs: SHA-256("eID-TOKEN-AUTH" ‖ rpUuid ‖ challenge) (docs/TOKEN_AUTH.md; Go
     * {@code TokenAuthDigest}). The token signs it with CKM_ECDSA (prehashed) and gives the raw r‖s to {@link #authVerify}.
     *
     * @param rpUuid the challenge answer's rpUUID (lower-case 36-character UUID)
     * @param challengeB64 the challenge (32 bytes, base64)
     * @throws IllegalArgumentException malformed rpUuid / challenge
     */
    public static byte[] tokenAuthDigest(String rpUuid, String challengeB64) {
        if (rpUuid == null || !RP_UUID.matcher(rpUuid).matches()) {
            throw new IllegalArgumentException("eid: token auth: rpUUID жижиг үсгийн 36 тэмдэгт UUID биш");
        }
        byte[] ch = challengeB64 == null ? null : SealService.b64(challengeB64);
        if (ch == null || ch.length != 32) throw new IllegalArgumentException("eid: token auth: challenge 32 байт base64 биш");
        MessageDigest h;
        try {
            h = MessageDigest.getInstance("SHA-256");
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        h.update(AUTH_TAG);
        h.update(rpUuid.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        h.update(ch);
        return h.digest();
    }

    /** Discovery's tokenCertificate block; absent (older CA) → enabled false. */
    public TokenCertInfo certificateInfo() {
        Json.Obj d = http.getJson(Routes.DISCOVERY_PATH, null).obj("GET " + Routes.DISCOVERY_PATH);
        Json.Obj t = d.optObj("tokenCertificate");
        if (t == null) return new TokenCertInfo(false, "", "", "", "", "", "", false, "", false, false, "");
        return new TokenCertInfo(t.optBool("enabled", false), t.optString("issue"), t.optString("result"), t.optString("permission"),
            t.optString("certificateLevel"), t.optString("keyAlgorithm"), t.optString("onBehalfOf"), t.optBool("scopeLockedOnRenewal", false),
            t.optString("appTransaction"), t.optBool("personalAutoSupersede", false), t.optBool("dryRun", false), Dto.text(t));
    }

    /**
     * The details of a 409 TOKEN_LIMIT_REACHED (Go {@code TokenLimitOf}); null for any other error or a body outside the
     * contract (the refusal stands, without details).
     */
    public static TokenLimit tokenLimitOf(Throwable err) {
        if (!(err instanceof EidException.Api) || !EidErrorCodes.TOKEN_LIMIT_REACHED.equals(((EidException.Api) err).code())) return null;
        Object v;
        try {
            v = Json.parse(((EidException.Api) err).body());
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!(v instanceof Json.Obj)) return null;
        Json.Obj b = (Json.Obj) v;
        Object lim = b.get("limit");
        if (!(lim instanceof Json.Num)) return null;
        Long l = ((Json.Num) lim).exactLong();
        if (l == null || l < 0 || l > Integer.MAX_VALUE) return null;
        String kind = b.optString("kind");
        switch (kind) {
            case KIND_PERSONAL:
                return new TokenLimit(kind, (int) (long) l, "");
            case KIND_ORGANIZATION:
                String org = b.optStringOrNull("organization");
                if (org == null || !org.startsWith("NTRMN-")) return null;
                return new TokenLimit(kind, (int) (long) l, org);
            default:
                return null;
        }
    }

    /** hexDigest is data's SHA-256 (case-insensitive; Go {@code hexSHA256Equal}, constant time). */
    static boolean hexSha256Equal(String hexDigest, byte[] data) {
        String h = hexDigest == null ? "" : hexDigest.strip();
        if (h.length() != 64) return false;
        byte[] want = new byte[32];
        for (int i = 0; i < 32; i++) {
            int hi = Character.digit(h.charAt(2 * i), 16);
            int lo = Character.digit(h.charAt(2 * i + 1), 16);
            if (hi < 0 || lo < 0) return false;
            want[i] = (byte) (hi << 4 | lo);
        }
        return MessageDigest.isEqual(EidCrypto.digest("SHA-256", data), want);
    }
}
