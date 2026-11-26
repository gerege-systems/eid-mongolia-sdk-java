package mn.eidmongolia.eid;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Sig;
import mn.eidmongolia.eid.pades.DocumentSealer;
import mn.eidmongolia.eid.pades.Registration;
import mn.eidmongolia.eid.pades.SealRegistration;

/**
 * Organisation e-Seal ({@link EidClient#seal()}, Go {@code SealService} seal.go + seal_grant.go, TS {@code SealApi}): a
 * digest is sealed with the organisation's key held by eID. Not interactive (no citizen, PIN or app) — the answer comes
 * directly. The RP needs {@code SEAL:<orgEtsi>} (else {@link EidException.Forbidden} 403), granted after the
 * organisation's registry-verified ADMIN approves with PIN2 ({@link #requestGrant}). Too many calls → 429
 * ({@link EidException.Api#retryable()} / {@link EidException.Api#retryAfter()}). Every 409 has a stable code
 * ({@link EidErrorCodes#SEAL}); the operator may switch issuance / sealing off platform-wide → 503
 * {@link EidErrorCodes#SEAL_SERVICE_DISABLED} ({@link EidException.SealServiceDisabled}, never retryable).
 *
 * <p>Sealing a PDF: {@link mn.eidmongolia.eid.pades.EidPades#sealPdf} (this class is its {@link DocumentSealer}); entering
 * the sealed PDF in the CA registry ({@code /verify/{docID}}): {@link #registerSealedPdf}.
 */
public final class SealService implements DocumentSealer {
    /** Longer than the CA's approval window (sign session TTL + 2 min). */
    public static final Duration DEFAULT_WAIT_TIMEOUT = Duration.ofMinutes(15);
    /** The CA recommends 2–5 s. */
    public static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(3);

    private static final Pattern UUID_LOWER = Pattern.compile("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$");
    /** The organisation identifier shape of the registration route (CA normalizeSealRegister). */
    private static final Pattern ORG_ETSI = Pattern.compile("^NTRMN-[0-9A-Z]{1,58}$");

    private final RpHttp http;
    private final Clock clock;
    private final DeviceLink.Sleeper sleeper;
    /** {@link #registerSealedPdf}'s HTTP timeout (EidClient pdfTimeout — the CA checks the CMS and the timestamp). */
    private final Duration registerTimeout;

    SealService(RpHttp http, Clock clock, DeviceLink.Sleeper sleeper, Duration registerTimeout) {
        this.http = http;
        this.clock = clock;
        this.sleeper = sleeper;
        this.registerTimeout = registerTimeout;
    }

    static byte[] b64(String s) {
        try {
            return Base64.getDecoder().decode(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /**
     * GET /seal/certificate/{orgEtsi}: the organisation's current (latest issued, active) seal certificate — the PAdES
     * signer certificate. No active certificate → 409 (CA 2026-11-12): {@link EidException.SealNotIssued},
     * {@link EidException.SealCertRevoked}, {@link EidException.SealCertExpired},
     * {@link EidException.SealCertNotYetValid}.
     *
     * @throws EidException.Validation {@link ValidationReasons#SEAL_RESPONSE}: no certificate in the answer
     */
    @Override
    public SealCertificate certificate(String orgEtsi) {
        String op = "GET /seal/certificate/…";
        SealCertificate c = SealCertificate.of(http.getJson(Routes.SEAL_CERTIFICATE.expand(orgEtsi), null).obj(op), op);
        if (c.certificate().length == 0) throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal certificate хоосон");
        return c;
    }

    /**
     * POST /seal/certificate/{orgEtsi}: a seal certificate REQUEST (202, PENDING); the organisation's ADMIN(s) approve
     * with PIN2 — poll with {@link #certificateRequest} / {@link #waitForCertificate}. A PENDING request already there is
     * returned (no new push). Errors: 409 {@link EidException.SealApproverUnavailable}, {@link EidException.OrgNotActive};
     * 403; 404; 429 (5 per organisation per hour); 503 {@link EidException.SealServiceDisabled} (service "issuance").
     */
    public SealCertificateRequest requestCertificate(String orgEtsi) {
        String op = "POST /seal/certificate/…";
        return checkRequest(SealCertificateRequest.of(http.postJson(Routes.SEAL_CERTIFICATE_REQUEST.expand(orgEtsi), Map.of(), null).obj(op), op));
    }

    /**
     * GET /seal/certificate/{orgEtsi}/requests/{requestId}: the request's state; {@link SealCertificateRequest#certificate()}
     * is set when ISSUED. Unknown (or another organisation's) → 404 {@link EidException.SealRequestNotFound}.
     */
    public SealCertificateRequest certificateRequest(String orgEtsi, String requestId) {
        String op = "GET /seal/certificate/…/requests/…";
        return checkRequest(SealCertificateRequest.of(
            http.getJson(Routes.SEAL_CERTIFICATE_REQUEST_STATUS.expand(orgEtsi, requestId), null).obj(op), op));
    }

    private static SealCertificateRequest checkRequest(SealCertificateRequest r) {
        if (r.requestId().isEmpty() || r.status().isEmpty()) {
            throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal хүсэлтийн хариунд requestId/status алга");
        }
        if (SealCertificateRequest.STATUS_ISSUED.equals(r.status()) && (r.certificate() == null || r.certificate().certificate().length == 0)) {
            throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "ISSUED seal хүсэлтэд certificate алга");
        }
        return r;
    }

    /**
     * Polls {@link #certificateRequest} every interval until ISSUED and returns the certificate (Go
     * {@code WaitForCertificate}). REJECTED / EXPIRED / FAILED → {@link EidException.SealRequestFailed} (a new request is
     * needed); the timeout → outcome {@link SealCertificateRequest#STATUS_TIMEOUT} (still PENDING). A temporary error
     * ({@link EidException.Api#retryable()}: 429/503 with Retry-After) waits max(interval, Retry-After) and goes on;
     * any other error (also 503 SEAL_SERVICE_DISABLED) is thrown. An interrupt → {@link EidException.Network} cancelled.
     *
     * @param o null = defaults (15 min / 3 s)
     */
    public SealCertificate waitForCertificate(String orgEtsi, String requestId, SealWaitOptions o) {
        Duration interval = positive(o == null ? null : o.interval(), DEFAULT_POLL_INTERVAL);
        Instant deadline = clock.instant().plus(positive(o == null ? null : o.timeout(), DEFAULT_WAIT_TIMEOUT));
        String op = "GET /seal/certificate/…/requests/…";
        while (true) {
            cancelled(op);
            Duration wait = interval;
            try {
                SealCertificateRequest r = certificateRequest(orgEtsi, requestId);
                switch (r.status()) {
                    case SealCertificateRequest.STATUS_ISSUED:
                        return r.certificate();
                    case SealCertificateRequest.STATUS_REJECTED:
                    case SealCertificateRequest.STATUS_EXPIRED:
                    case SealCertificateRequest.STATUS_FAILED:
                        throw new EidException.SealRequestFailed(r.status(), r.requestId(), r.failure());
                    default:
                        break;
                }
            } catch (EidException.Api e) {
                if (!e.retryable()) throw e;
                wait = max(interval, e.retryAfter());
            }
            Duration left = Duration.between(clock.instant(), deadline);
            if (left.isZero() || left.isNegative()) {
                throw new EidException.SealRequestFailed(SealCertificateRequest.STATUS_TIMEOUT, requestId, "");
            }
            sleep(wait.compareTo(left) < 0 ? wait : left, op);
        }
    }

    /**
     * POST /seal/{orgEtsi}: seals {@code digest} with the organisation's e-Seal (Go {@code Seal}). The response's
     * signature is verified over the digest with the response's certificate, which must be an e-Seal certificate
     * ({@link #isSealCertificate}) — else {@link EidException.Validation}. Chain / revocation are NOT checked here
     * ({@link mn.eidmongolia.eid.pades.EidPades#sealPdf} does OCSP/CRL + self-validation). Errors: 403 (no
     * {@code SEAL:<orgEtsi>}), 429 (300 per RP per minute; retryable), 503 {@link EidException.SealServiceDisabled}
     * (service "sealing", not retryable), 409 {@link EidErrorCodes#SEAL} codes.
     *
     * @param hash SHA-256 | SHA-384 | SHA-512 (null = SHA-256); the digest length must match
     * @throws IllegalArgumentException the digest length does not match the hash (no request is sent)
     */
    @Override
    public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash) {
        return seal(orgEtsi, digest, hash, null, 0);
    }

    /**
     * {@link #seal(String, byte[], HashAlgorithm)} that also reserves the stamp's document position on the CA
     * ({@code /verify/<docId>/<revIndex>}, CA V158 dto.SealRequest docId / revIndex) for a seal stamp that draws a QR. Both
     * or neither: docId null/"" with revIndex 0 sends neither. Go / TS {@code SealForDocument} / {@code sealForDocument} (SHA-256
     * only) = {@link #sealForDocument}.
     *
     * @param docId a lowercase UUID
     * @param revIndex the signature's position in the document (1…16, the CA's bound)
     * @throws IllegalArgumentException a bad digest length, or docId / revIndex not both valid (no request is sent)
     */
    public SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash, String docId, int revIndex) {
        HashAlgorithm h = hash == null ? HashAlgorithm.SHA_256 : hash;
        int size = Prehashed.hashLen(h.wireName());
        if (digest == null || digest.length != size) {
            throw new IllegalArgumentException("eid: digest нь " + h.wireName() + "-ийн урт (" + size + " байт) байх ёстой");
        }
        boolean ref = docId != null && !docId.isEmpty();
        if (ref != (revIndex != 0) || (ref && (!UUID_LOWER.matcher(docId).matches() || revIndex < 1 || revIndex > PdfService.MAX_REV_INDEX))) {
            throw new IllegalArgumentException("eid: seal: docId (жижиг үсгийн UUID) ба revIndex (1…16) хоёулаа эсвэл аль нь ч үгүй");
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("digest", Base64.getEncoder().encodeToString(digest));
        body.put("hashType", h.wireName().replace("-", ""));
        if (ref) {
            body.put("docId", docId);
            body.put("revIndex", revIndex);
        }
        RpHttp.Result res = http.postJson(Routes.SEAL.expand(orgEtsi), body, null);
        Json.Obj r = res.obj("POST /seal/…");
        Json.Obj sig = r.optObj("signature");
        Json.Obj cert = r.optObj("cert");
        if (sig == null || sig.optString("value").isEmpty() || cert == null || cert.optString("value").isEmpty()) {
            throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal хариунд signature/cert алга");
        }
        byte[] sigDer = b64(sig.optString("value"));
        if (sigDer == null) throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal signature base64 биш");
        byte[] certDer = b64(cert.optString("value"));
        if (certDer == null) throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal cert base64 биш");
        Cert c;
        try {
            c = Cert.parse(certDer);
        } catch (IllegalArgumentException e) {
            throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "seal cert задарсангүй", e);
        }
        if (!isSeal(c)) throw new EidException.Validation(ValidationReasons.SEAL_NOT_ESEAL, "хариуны гэрчилгээ e-Seal биш (KeyUsage)");
        if (!c.isEc() || !verifyEcdsaDer(c, digest, sigDer)) {
            throw new EidException.Validation(ValidationReasons.SEAL_SIGNATURE, "seal гарын үсэг digest-тэй таарсангүй");
        }
        return new SealResult(r.optString("orgEtsi"), sigDer, sig.optString("signatureAlgorithm"), certDer, cert.optString("certificateLevel"),
            Dto.instant(r, "sealedAt", "POST /seal/…"), Dto.raw(res));
    }

    /**
     * POST /seal/{orgEtsi} {digest, hashType: SHA256, docId, revIndex} (CA V158; Go {@code SealForDocument}, TS
     * {@code sealForDocument}): {@link #seal(String, byte[], HashAlgorithm)} plus the QR seal's document reservation — the
     * stamp's QR ({@code /verify/<docId>/<revIndex>}) cannot be taken by another registration (the CA blocks the docId's
     * later positions with DOC_ID_CONFLICT / DOC_ID_RESERVED for 7 days while the reservation is unregistered). SHA-256
     * digests only. A registration whose docID / revIndex differ from the reservation → 409
     * {@link EidException.SealDocMismatch}. {@link mn.eidmongolia.eid.pades.EidPades#sealPdf} calls it for
     * {@code SealOptions.qr(true)}.
     *
     * @throws IllegalArgumentException docId not a lowercase UUID, revIndex outside 1–16, or a digest that is not 32 bytes
     *     (no request is sent; the CA would answer 400 REQUEST_INVALID)
     */
    @Override
    public SealResult sealForDocument(String orgEtsi, byte[] digest, String docId, int revIndex) {
        if (docId == null || !UUID_LOWER.matcher(docId).matches() || revIndex < 1 || revIndex > PdfService.MAX_REV_INDEX) {
            throw new IllegalArgumentException("eid: sealForDocument: docId жижиг үсгийн UUID, revIndex 1–16");
        }
        return seal(orgEtsi, digest, HashAlgorithm.SHA_256, docId, revIndex);
    }

    /**
     * POST /seal/{orgEtsi}/registrations ({@code SEAL:<orgEtsi>}, CA V158; Go {@code RegisterSealedPDF}, TS
     * {@code registerSealedPdf}): enters an organisation-sealed PDF in the CA registry ({@code /verify/{docID}}, the
     * organisation's row) — the seal counterpart of {@link PdfService#registerSignature}. The body is
     * {@link mn.eidmongolia.eid.pades.Completed#sealRegistration()} after {@code EidPades.sealPdf}. The CA requires that THIS
     * RP sealed it via POST /seal/{orgEtsi} (the CMS's SHA-256(signedAttrs) = the sealed digest), within 7 days, matching
     * the docId / revIndex reserved by {@link #sealForDocument}. A repeat of the same body is idempotent (200,
     * {@link PdfSignatureRegistered#created()} false; also after the 7 days).
     *
     * <p>On 409 PRIOR_MISMATCH, when {@link SealRegistration#priorSignatures()} covers every prior signature and no
     * priorRevisionSha256 was given, the revision splits are retried exactly as {@link PdfService#registerSignature} does.
     *
     * @throws IllegalArgumentException orgEtsi not NTRMN-…, or a body that breaks {@link SealRegistration#validate()} (no
     *     request is sent)
     * @throws EidException.Api code ∈ {@link EidErrorCodes#SEAL_REGISTER} ({@link EidException.SealNotFound},
     *     {@link EidException.SealDocMismatch}, {@link EidException.DocIdReserved}; 429 RATE_LIMITED — 600 per RP per 10
     *     minutes, retryable); {@link EidException.Forbidden} 403 (no {@code SEAL:<orgEtsi>}); 501 (PAdES not configured
     *     on the CA). The sealing switch and billing do not apply.
     */
    public PdfSignatureRegistered registerSealedPdf(String orgEtsi, SealRegistration registration) {
        String org = orgEtsi == null ? "" : orgEtsi.strip();
        if (!ORG_ETSI.matcher(org.toUpperCase(java.util.Locale.ROOT)).matches()) {
            throw new IllegalArgumentException("eid: registerSealedPdf: orgEtsi нь NTRMN-…");
        }
        if (registration == null) throw new IllegalArgumentException("eid: registerSealedPdf: registration заавал");
        registration.validate();
        java.util.List<Registration.PriorSignature> prior = registration.priorSignatures();
        boolean manual = registration.priorRevisionSha256() != null && !registration.priorRevisionSha256().isEmpty();
        try {
            return registerSealed(org, registration);
        } catch (EidException.Api first) {
            if (!EidErrorCodes.PRIOR_MISMATCH.equals(first.code()) || manual || prior.isEmpty() || prior.size() != registration.revIndex() - 1) {
                throw first;
            }
            // Which prior row is CA-assembled (mode A) cannot be told from the file — the same splits as registerSignature.
            for (boolean[] asRevision : PdfService.priorSplits(prior.size())) {
                SealRegistration next = registration.withPriorByRevision(asRevision);
                next.validate();
                try {
                    return registerSealed(org, next);
                } catch (EidException.Api e) {
                    if (!EidErrorCodes.PRIOR_MISMATCH.equals(e.code())) throw e;
                }
            }
            throw first;
        }
    }

    private PdfSignatureRegistered registerSealed(String org, SealRegistration r) {
        String path = Routes.SEAL_REGISTRATIONS.expand(org);
        RpHttp.Result res = http.exchange("POST", path, EidCrypto.utf8(r.toJson()), "application/json", registerTimeout);
        Json.Obj o = res.obj("POST /seal/…/registrations");
        long rev = o.optLong("revIndex", 0);
        String doc = o.optString("docID");
        return new PdfSignatureRegistered(doc.isEmpty() ? r.docID() : doc, (int) Math.max(Integer.MIN_VALUE, Math.min(Integer.MAX_VALUE, rev)),
            o.optString("registeredAt"), o.optString("verifyUrl"), res.status() == 201);
    }

    /** Go {@code ecdsa.VerifyASN1}: a DER (r, s), 0 < r, s < n, over the prehashed digest ({@link Sig#verify}). */
    private static boolean verifyEcdsaDer(Cert c, byte[] digest, byte[] sig) {
        return Sig.verify("NONEwithECDSA", c.publicKey(), digest, sig);
    }

    /**
     * The e-Seal profile (Go {@code IsSealCertificate}): not a CA, KeyUsage has nonRepudiation (contentCommitment) and NOT
     * digitalSignature, and no EKU purpose (extendedKeyUsage absent or empty). A certificate that does not parse → false.
     */
    public static boolean isSealCertificate(X509Certificate cert) {
        if (cert == null) return false;
        try {
            return isSeal(Cert.parse(cert.getEncoded()));
        } catch (CertificateEncodingException | IllegalArgumentException e) {
            return false;
        }
    }

    /** {@link #isSealCertificate} on DER. */
    public static boolean isSealCertificate(byte[] der) {
        try {
            return isSeal(Cert.parse(der));
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static boolean isSeal(Cert c) {
        if (c == null || c.isCa()) return false;
        boolean[] ku = c.x509.getKeyUsage();
        boolean nonRep = ku != null && ku.length > 1 && ku[1];
        boolean digSig = ku != null && ku.length > 0 && ku[0];
        return nonRep && !digSig && c.extKeyUsage().isEmpty();
    }

    // ── seal grants (Go seal_grant.go, CA V156) ──

    /**
     * POST /seal/grants {orgEtsi, sessionId}: a request for the right to use the organisation's seal (202, PENDING). The
     * person is identified by an AUTHENTICATION session THIS RP started and completed OK within the last 5 minutes; they
     * must be the organisation's registry CEO — the push goes only to them. Same session again → the same PENDING.
     * Errors: 400; 403 {@link EidException.Forbidden} (RP_NOT_REGISTERED, NOT_ORG_CEO); 404
     * {@link EidException.AuthSessionNotFound}, ORG_NOT_FOUND; 409 {@link EidErrorCodes#SEAL_GRANT} codes; 429.
     *
     * @throws IllegalArgumentException orgEtsi or sessionId blank (no request is sent)
     */
    public SealGrant requestGrant(String orgEtsi, String sessionId) {
        String org = orgEtsi == null ? "" : orgEtsi.strip();
        String sid = sessionId == null ? "" : sessionId.strip();
        if (org.isEmpty() || sid.isEmpty()) throw new IllegalArgumentException("eid: RequestGrant: orgEtsi ба sessionID шаардлагатай");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("orgEtsi", org);
        body.put("sessionId", sid);
        String op = "POST /seal/grants";
        return checkGrant(SealGrant.of(http.postJson(Routes.SEAL_GRANTS.expand(), body, null).obj(op), op));
    }

    /**
     * GET /seal/grants/{grantId}: the request's state. Unknown or another RP's → 404 {@link EidException.SealGrantNotFound}.
     *
     * @throws IllegalArgumentException grantId blank
     */
    public SealGrant grantStatus(String grantId) {
        String id = grantId == null ? "" : grantId.strip();
        if (id.isEmpty()) throw new IllegalArgumentException("eid: GrantStatus: grantID шаардлагатай");
        String op = "GET /seal/grants/…";
        return checkGrant(SealGrant.of(http.getJson(Routes.SEAL_GRANT_STATUS.expand(id), null).obj(op), op));
    }

    private static SealGrant checkGrant(SealGrant g) {
        if (g.grantId().isEmpty() || g.status().isEmpty()) {
            throw new EidException.Validation(ValidationReasons.SEAL_RESPONSE, "тамганы эрхийн хариунд grantId/status алга");
        }
        return g;
    }

    /**
     * Polls {@link #grantStatus} until APPROVED (Go {@code WaitForGrant}). REJECTED / EXPIRED / FAILED / REVOKED →
     * {@link EidException.SealGrantFailed}; the timeout → outcome {@link SealGrant#STATUS_TIMEOUT}. Retryable errors as
     * {@link #waitForCertificate}.
     *
     * @param o null = defaults (15 min / 3 s)
     */
    public SealGrant waitForGrant(String grantId, SealWaitOptions o) {
        Duration interval = positive(o == null ? null : o.interval(), DEFAULT_POLL_INTERVAL);
        Instant deadline = clock.instant().plus(positive(o == null ? null : o.timeout(), DEFAULT_WAIT_TIMEOUT));
        String op = "GET /seal/grants/…";
        while (true) {
            cancelled(op);
            Duration wait = interval;
            try {
                SealGrant g = grantStatus(grantId);
                switch (g.status()) {
                    case SealGrant.STATUS_APPROVED:
                        return g;
                    case SealGrant.STATUS_REJECTED:
                    case SealGrant.STATUS_EXPIRED:
                    case SealGrant.STATUS_FAILED:
                    case SealGrant.STATUS_REVOKED:
                        throw new EidException.SealGrantFailed(g.status(), g.grantId(), g.failure());
                    default:
                        break;
                }
            } catch (EidException.Api e) {
                if (!e.retryable()) throw e;
                wait = max(interval, e.retryAfter());
            }
            Duration left = Duration.between(clock.instant(), deadline);
            if (left.isZero() || left.isNegative()) throw new EidException.SealGrantFailed(SealGrant.STATUS_TIMEOUT, grantId, "");
            sleep(wait.compareTo(left) < 0 ? wait : left, op);
        }
    }

    private static Duration positive(Duration d, Duration def) {
        return d == null || d.isZero() || d.isNegative() ? def : d;
    }

    private static Duration max(Duration a, Duration b) {
        return a.compareTo(b) >= 0 ? a : b;
    }

    private static void cancelled(String op) {
        if (Thread.currentThread().isInterrupted()) {
            throw new EidException.Network(op, false, true, new InterruptedException());
        }
    }

    private void sleep(Duration d, String op) {
        try {
            sleeper.sleep(d);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new EidException.Network(op, false, true, e);
        }
    }
}
