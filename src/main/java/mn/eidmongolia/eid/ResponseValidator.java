package mn.eidmongolia.eid;

import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Der;
import mn.eidmongolia.eid.internal.Text;

/**
 * Validates RP-API session results CRYPTOGRAPHICALLY (Go {@code Validator}, TS {@code ResponseValidator}) — the SDK's
 * main security layer: {@code endResult == OK} alone is NEVER trusted (a broken or proxied RP-API could forge it):
 *
 * <ol>
 *   <li>state COMPLETE and endResult OK ({@link EidException.SessionFailed} otherwise);
 *   <li>the citizen certificate chains to a trust anchor (Mongolian National Root CA) — a deterministic hand-written
 *       path builder (TS validator.ts {@code verifyChain}; no PKIX / OS chain engine): CA:TRUE, keyCertSign,
 *       pathLenConstraint, EKU nesting, validity; fail-closed: any CA with nameConstraints and any critical extension the
 *       SDK does not handle → rejected;
 *   <li>the certificate (and its chain) is valid, has the purpose (auth / sign) and the required certLevel; the issuer is
 *       allowed;
 *   <li>the signature verifies with the citizen's key: auth → the ACSP_V2 payload, sign → the RP's digest.
 * </ol>
 *
 * <p>Any failure → {@link EidException.Validation} with a stable {@link EidException.Validation#reason()} key
 * ({@link ValidationReasons}) — do NOT trust the response. Revocation is a separate, networked step
 * ({@link #checkRevocation}). Thread-safe.
 */
public final class ResponseValidator {
    /** ACSP_V2 — authentication responses. */
    public static final String PROTOCOL_ACSP_V2 = "ACSP_V2";
    /** RAW_DIGEST_SIGNATURE — signature and certificate-choice responses. */
    public static final String PROTOCOL_RAW_DIGEST = "RAW_DIGEST_SIGNATURE";

    private static final String OID_QC_STATEMENTS = "1.3.6.1.5.5.7.1.3";
    private static final String OID_QC_COMPLIANCE = "0.4.0.1862.1.1";
    private static final String OID_QC_SSCD = "0.4.0.1862.1.4";
    /** The Mongolian national PKI certificate policy (CA crypto/ca_policy.go NationalPolicyOID). */
    private static final String OID_POLICY_NATIONAL = "2.16.496.1.101.1.2.8";
    private static final String OID_KEY_USAGE = "2.5.29.15";
    private static final String OID_NAME_CONSTRAINTS = "2.5.29.30";
    private static final String EKU_ANY = "2.5.29.37.0";
    private static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
    private static final String EKU_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4";
    /** The critical extensions the SDK understands — {@link Cert#HANDLED_CRITICAL} (TS HANDLED_CRITICAL, Go handledCritical). */
    private static final Set<String> HANDLED_CRITICAL = Cert.HANDLED_CRITICAL;
    /** The smallest RSA modulus accepted for a citizen, CA or OCSP-responder key (as EidQr.MIN_RSA_BITS). */
    static final int MIN_RSA_BITS = 2048;
    private static final Map<String, Integer> LEVEL_RANK = Map.of("ADVANCED", 1, "QUALIFIED", 2, "QSCD", 3);
    private static final Pattern USER_CHALLENGE = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    /** KeyUsage bit indices (X509Certificate#getKeyUsage). */
    private static final int KU_DIGITAL_SIGNATURE = 0;
    private static final int KU_NON_REPUDIATION = 1;
    private static final int KU_KEY_ENCIPHERMENT = 2;
    private static final int KU_KEY_CERT_SIGN = 5;
    private static final int MAX_PATH = 8;

    private final List<Cert> anchors;
    private final List<Cert> intermediates;
    private final CertificateLevel requiredLevel;
    private final Duration skew;
    private final boolean allowUntrusted;
    private final RevocationChecker revocation;
    private final RevocationMode revocationMode;
    /** null = no issuer allowlist. */
    private final Set<String> allowedIssuers;
    private final boolean checkKeyUsage;
    private final String schemeName;
    private final Clock clock;

    /**
     * Parses the trust configuration (Go {@code NewValidator}).
     *
     * @throws IllegalArgumentException a PEM without a certificate, a certificate that does not parse, or an issuer SKI
     *     that is not hex
     */
    public ResponseValidator(TrustConfig trust) {
        this(trust, Clock.systemUTC());
    }

    ResponseValidator(TrustConfig trust, Clock clock) {
        TrustConfig t = trust == null ? TrustConfig.builder().build() : trust;
        this.anchors = parseCerts(t.trustAnchorsPem, "TrustAnchorsPEM");
        this.intermediates = parseCerts(t.intermediatesPem == null ? Roots.CITIZEN_INTERMEDIATES_PEM : t.intermediatesPem, "IntermediatesPEM");
        List<String> skis = t.allowedIssuerSkis;
        if (skis.isEmpty() && !t.allowAnyIssuer && !anchors.isEmpty()) {
            // The default allowlist only when the chain is checked — without an anchor (allowUntrusted) there is no issuer.
            skis = List.of(Roots.CITIZEN_ISSUING_CA_SKI);
        }
        Set<String> issuers = null;
        for (String s : skis) {
            String ski = (s == null ? "" : s.strip()).replace(":", "").toLowerCase(Locale.ROOT);
            if (ski.isEmpty() || ski.length() % 2 != 0 || !ski.matches("[0-9a-f]+")) {
                throw new IllegalArgumentException("eid: AllowedIssuerSKIs: \"" + s + "\" hex key identifier биш");
            }
            if (issuers == null) issuers = new HashSet<>();
            issuers.add(ski);
        }
        this.allowedIssuers = issuers;
        this.requiredLevel = t.requiredLevel == null ? CertificateLevel.QUALIFIED : t.requiredLevel;
        this.skew = t.clockSkew == null || t.clockSkew.isNegative() ? Duration.ZERO : t.clockSkew;
        this.allowUntrusted = t.allowUntrusted;
        this.revocation = t.revocation;
        this.revocationMode = t.revocationMode == null ? RevocationMode.HARD_FAIL : t.revocationMode;
        this.checkKeyUsage = !t.skipKeyUsageCheck;
        this.schemeName = t.schemeName;
        this.clock = clock == null ? Clock.systemUTC() : clock;
    }

    /** Go {@code parseCerts}: every string must hold at least one CERTIFICATE block. */
    private static List<Cert> parseCerts(List<String> pems, String what) {
        List<Cert> out = new ArrayList<>();
        for (String s : pems) {
            List<byte[]> blocks = Cert.pemBlocks(s == null ? "" : s);
            if (blocks.isEmpty()) throw new IllegalArgumentException("eid: " + what + ": PEM CERTIFICATE блок алга");
            for (byte[] der : blocks) {
                try {
                    out.add(Cert.parse(der));
                } catch (RuntimeException e) {
                    throw new IllegalArgumentException("eid: " + what + ": " + e.getMessage(), e);
                }
            }
        }
        return Collections.unmodifiableList(out);
    }

    private static EidException.Validation invalid(String reason, String detail) {
        return new EidException.Validation(reason, detail);
    }

    // ── public API ──

    /** {@link #validateAuth(SessionResult, AcspContext, ValidateAuthOptions)} without extra checks. */
    public VerifiedIdentity validateAuth(SessionResult r, AcspContext acsp) {
        return validateAuth(r, acsp, ValidateAuthOptions.NONE);
    }

    /**
     * Fully validates an authentication result and returns the verified citizen (Go {@code ValidateAuth}). Check
     * revocation afterwards with {@link #checkRevocation}.
     *
     * @param acsp the context the SDK returned at session start (stored by the RP)
     * @param o null = no extra checks
     * @throws EidException.SessionFailed endResult ≠ OK
     * @throws EidException.Validation anything else — do not trust the response
     */
    public VerifiedIdentity validateAuth(SessionResult r, AcspContext acsp, ValidateAuthOptions o) {
        ValidateAuthOptions opts = o == null ? ValidateAuthOptions.NONE : o;
        if (acsp == null) throw invalid(ValidationReasons.AUTH_ACSP_MISSING, "ACSP контекст алга");
        Leaf l = precheck(r, PROTOCOL_ACSP_V2);
        byte[] sr = decodeStd(nz(r.serverRandom()));
        if (sr == null || sr.length < 18) throw invalid(ValidationReasons.AUTH_SERVER_RANDOM, "serverRandom алга/богино");
        if (!USER_CHALLENGE.matcher(nz(r.userChallenge())).matches()) {
            throw invalid(ValidationReasons.AUTH_USER_CHALLENGE, "userChallenge буруу хэлбэртэй");
        }
        FlowType flow = FlowType.fromWire(nz(r.flowType()));
        if (flow == null || !acsp.flowTypes().contains(flow)) {
            throw invalid(ValidationReasons.AUTH_FLOW_NOT_OFFERED, "flowType " + nz(r.flowType()) + " нь санал болгосон урсгалд байхгүй");
        }
        FlowType expected = opts.expectedFlowType;
        if (expected != null && flow != expected) {
            throw invalid(ValidationReasons.FLOW_MISMATCH, "flowType " + nz(r.flowType()) + " ≠ эхлүүлсэн урсгал " + expected.wireName()
                + " (relay байж болзошгүй)");
        }
        String verifier = opts.userChallengeVerifier;
        boolean sameDevice = expected == FlowType.WEB2APP || expected == FlowType.APP2APP;
        if (sameDevice && (verifier == null || verifier.isEmpty())) {
            throw invalid(ValidationReasons.AUTH_VERIFIER_REQUIRED, expected.wireName() + " урсгалд callback-ийн userChallengeVerifier заавал");
        }
        // Compared whenever given — also "" (TS rule, stricter than Go): a callback whose verifier was blanked must fail.
        if (verifier != null && !EidCrypto.userChallengeOf(verifier).equals(nz(r.userChallenge()))) {
            throw invalid(ValidationReasons.AUTH_VERIFIER_MISMATCH, "userChallengeVerifier нь гарын үсэг зурагдсан userChallenge-тэй таарсангүй");
        }
        if (nz(r.interactionTypeUsed()).isEmpty()) throw invalid(ValidationReasons.AUTH_INTERACTION_TYPE_MISSING, "interactionTypeUsed алга");
        String[] ah = algorithmOf(r, l.cert.publicKey(), wire(acsp.signatureAlgorithm()), wire(acsp.hashAlgorithm()));
        String cb = signedCallbackUrl(r.initialCallbackUrl(), acsp.initialCallbackUrl(), nz(r.flowType()));
        byte[] payload = Acsp.buildV2Payload(new AcspV2Params(schemeName, nz(r.serverRandom()), acsp.rpChallenge(), nz(r.userChallenge()),
            acsp.relyingPartyName(), acsp.brokeredRpName(), acsp.interactions(), nz(r.interactionTypeUsed()), cb, nz(r.flowType())));
        if (!EidCrypto.verifyPayloadSignature(payload, nz(r.signatureValueB64()), l.cert.publicKey(), ah[0], ah[1])) {
            throw invalid(ValidationReasons.AUTH_SIGNATURE, "auth гарын үсэг ACSP_V2 payload-той таарсангүй (хуурамч хариу байж болзошгүй)");
        }
        return new VerifiedIdentity(nz(r.documentNumber()), l.cert.x509, Subject.of(l.cert), subjectDn(l.cert), l.level);
    }

    /** {@link #validateSign(SessionResult, String, HashAlgorithm, ValidateSignOptions)} with SHA-256 and no extra checks. */
    public VerifiedSignature validateSign(SessionResult r, String digestB64) {
        return validateSign(r, digestB64, null, ValidateSignOptions.NONE);
    }

    /** {@link #validateSign(SessionResult, String, HashAlgorithm, ValidateSignOptions)} without extra checks. */
    public VerifiedSignature validateSign(SessionResult r, String digestB64, HashAlgorithm hash) {
        return validateSign(r, digestB64, hash, ValidateSignOptions.NONE);
    }

    /**
     * Fully validates a signature result and returns the verified signature (Go {@code ValidateSign}).
     *
     * @param digestB64 the digest sent in the request (base64)
     * @param hash the hash that produced it; null = SHA-256
     * @param o null = no extra checks
     * @throws EidException.SessionFailed endResult ≠ OK
     * @throws EidException.Validation anything else — do not trust the response
     */
    public VerifiedSignature validateSign(SessionResult r, String digestB64, HashAlgorithm hash, ValidateSignOptions o) {
        ValidateSignOptions opts = o == null ? ValidateSignOptions.NONE : o;
        Leaf l = precheck(r, PROTOCOL_RAW_DIGEST);
        if (opts.expectedFlowType != null && FlowType.fromWire(nz(r.flowType())) != opts.expectedFlowType) {
            throw invalid(ValidationReasons.FLOW_MISMATCH, "flowType " + nz(r.flowType()) + " ≠ эхлүүлсэн урсгал "
                + opts.expectedFlowType.wireName() + " (relay байж болзошгүй)");
        }
        if (opts.expectedCertificate != null) {
            byte[] want;
            try {
                want = opts.expectedCertificate.getEncoded();
            } catch (CertificateEncodingException e) {
                want = new byte[0];
            }
            if (!Arrays.equals(l.cert.raw, want)) {
                throw invalid(ValidationReasons.SIGN_CERTIFICATE_MISMATCH, "гэрчилгээ certificate-choice-оор сонгосонтой таарахгүй (serial "
                    + l.cert.serial.toString(16) + " ≠ " + opts.expectedCertificate.getSerialNumber().toString(16) + ")");
            }
        }
        String want = hash == null ? HashAlgorithm.SHA_256.wireName() : hash.wireName();
        byte[] digest = decodeStd(digestB64);
        if (digest == null) throw invalid(ValidationReasons.SIGN_DIGEST_BASE64, "digest base64 буруу");
        String expectedAlg = opts.expectedAlgorithm == null ? "" : opts.expectedAlgorithm.wireName();
        String[] ah = algorithmOf(r, l.cert.publicKey(), expectedAlg, want);
        if (digest.length != Prehashed.hashLen(ah[1])) throw invalid(ValidationReasons.SIGN_DIGEST_LENGTH, "digest урт hashAlgorithm-тай таарахгүй");
        if (!Prehashed.verify(digest, nz(r.signatureValueB64()), l.cert.publicKey(), ah[0], ah[1])) {
            throw invalid(ValidationReasons.SIGN_SIGNATURE, "гарын үсэг өгсөн digest-тэй таарсангүй");
        }
        return new VerifiedSignature(nz(r.documentNumber()), nz(r.signatureValueB64()), nz(r.signatureAlgorithm()), l.cert.x509, Subject.of(l.cert),
            subjectDn(l.cert), l.level);
    }

    /**
     * Validates a certificate-choice result (Go {@code ValidateCertificateChoice}, TS {@code validateCertificateChoice}):
     * COMPLETE/OK, certificate and documentNumber present, validity, purpose (signing — nonRepudiation), chain, issuer,
     * level. This response carries NO signature — the citizen is not authenticated; it only tells the next sign
     * session's certificate in advance.
     *
     * @param certChoiceSessionId the certificate-choice session (linked signing's linkedSessionID)
     */
    public Signer validateCertificateChoice(SessionResult r, String certChoiceSessionId) {
        SessionService.requireOk(r);
        Leaf l = leafOf(r, PROTOCOL_RAW_DIGEST);
        return new Signer(nz(r.documentNumber()), l.cert.x509, Base64.getEncoder().encodeToString(l.cert.raw), l.level, Subject.of(l.cert),
            certChoiceSessionId);
    }

    /**
     * Checks revocation with the configured {@link TrustConfig.Builder#revocation} checker (Go {@code CheckRevocation}).
     * No checker → no-op. Revoked, and unknown in hard-fail mode → {@link EidException.Validation}; a checker failure →
     * {@link EidException} (do not trust). Call after validateAuth / validateSign.
     */
    public void checkRevocation(X509Certificate cert) {
        checkRevocationStatus(cert);
    }

    /** {@link #checkRevocation} that also says what it decided (logs / audit; Go {@code CheckRevocationStatus}). */
    public RevocationOutcome checkRevocationStatus(X509Certificate cert) {
        return checkRevocationWith(cert, revocation, revocationMode);
    }

    /**
     * {@link #checkRevocationStatus} with the given checker and mode instead of the trust configuration's; the issuer is
     * looked up in the validator's trust pool (Go {@code CheckRevocationWith}).
     *
     * @param checker null → {@link RevocationOutcome#SKIPPED}
     * @param mode null = {@link RevocationMode#HARD_FAIL}
     */
    public RevocationOutcome checkRevocationWith(X509Certificate cert, RevocationChecker checker, RevocationMode mode) {
        if (checker == null) return RevocationOutcome.SKIPPED;
        X509Certificate issuer = null;
        if (cert != null) {
            try {
                Cert is = findIssuer(Cert.parse(cert.getEncoded()));
                issuer = is == null ? null : is.x509;
            } catch (CertificateEncodingException | RuntimeException e) {
                issuer = null;
            }
        }
        RevocationStatus status;
        EidException.Ocsp noAnswer = null;
        try {
            status = checker.check(cert, issuer);
        } catch (EidException.Ocsp e) {
            // OcspRevocationChecker without an answer — "unknown"; the mode decides, the reason is kept.
            status = RevocationStatus.UNKNOWN;
            noAnswer = e;
        } catch (RuntimeException e) {
            throw new EidException("eid: revocation шалгалт: " + e.getMessage(), e);
        }
        if (status == RevocationStatus.GOOD) return RevocationOutcome.GOOD;
        if (status == RevocationStatus.REVOKED) throw invalid(ValidationReasons.REVOCATION_REVOKED, "гэрчилгээ цуцлагдсан (revoked)");
        if (mode == RevocationMode.SOFT_FAIL) return RevocationOutcome.UNCHECKED;
        if (noAnswer != null) {
            throw new EidException.Validation(ValidationReasons.REVOCATION_UNKNOWN,
                "гэрчилгээний revocation төлөв тогтоогдсонгүй (hard-fail): " + noAnswer.getMessage(), noAnswer);
        }
        throw invalid(ValidationReasons.REVOCATION_UNKNOWN, "гэрчилгээний revocation төлөв тогтоогдсонгүй (hard-fail)");
    }

    // ── response checks (Go validator.go) ──

    private static final class Leaf {
        final Cert cert;
        final CertificateLevel level;

        Leaf(Cert cert, CertificateLevel level) {
            this.cert = cert;
            this.level = level;
        }
    }

    private static String nz(String s) {
        return s == null ? "" : s;
    }

    private static String wire(SignatureAlgorithm a) {
        return a == null ? "" : a.wireName();
    }

    private static String wire(HashAlgorithm h) {
        return h == null ? "" : h.wireName();
    }

    private static String subjectDn(Cert c) {
        return c.x509.getSubjectX500Principal().getName();
    }

    /** Strict standard base64 (Go StdEncoding), else null. */
    private static byte[] decodeStd(String s) {
        try {
            return Base64.getDecoder().decode(s == null ? "" : s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    /** Go {@code precheck}: state/endResult, protocol, certificate and signature present, then {@link #leafOf}. */
    private Leaf precheck(SessionResult r, String protocol) {
        SessionService.requireOk(r);
        if (!nz(r.signatureProtocol()).isEmpty() && !nz(r.signatureProtocol()).equals(protocol)) {
            throw invalid(ValidationReasons.PROTOCOL_MISMATCH, "signatureProtocol " + nz(r.signatureProtocol()) + " ≠ " + protocol);
        }
        if (nz(r.certificateDerB64()).isEmpty()) throw invalid(ValidationReasons.NO_CERTIFICATE, "хариунд гэрчилгээ алга");
        if (nz(r.signatureValueB64()).isEmpty()) throw invalid(ValidationReasons.NO_SIGNATURE, "хариунд гарын үсэг алга");
        return leafOf(r, protocol);
    }

    /** Go {@code leafOf}: documentNumber, parse, validity, purpose, chain, issuer, level. */
    private Leaf leafOf(SessionResult r, String protocol) {
        if (nz(r.certificateDerB64()).isEmpty()) throw invalid(ValidationReasons.NO_CERTIFICATE, "хариунд гэрчилгээ алга");
        if (nz(r.documentNumber()).isEmpty()) throw invalid(ValidationReasons.NO_DOCUMENT_NUMBER, "хариунд documentNumber алга");
        byte[] der = decodeStd(nz(r.certificateDerB64()));
        if (der == null) throw invalid(ValidationReasons.CERT_MALFORMED, "гэрчилгээ base64 буруу");
        Cert leaf;
        try {
            leaf = Cert.parse(der);
        } catch (RuntimeException e) {
            throw invalid(ValidationReasons.CERT_MALFORMED, "гэрчилгээ задарсангүй");
        }
        Instant now = clock.instant();
        checkValidity(leaf, now);
        verifyCertificate(leaf, protocol, now);
        CertificateLevel fromCert = certificateLevelOf(leaf, protocol);
        CertificateLevel level = effectiveLevel(nz(r.certificateLevel()), fromCert);
        checkLevel(level);
        return new Leaf(leaf, level);
    }

    /** Go {@code checkValidity}: the message names the serial (hex), never the subject (the citizen's name / PNOMN). */
    private void checkValidity(Cert c, Instant now) {
        if (now.plus(skew).isBefore(c.x509.getNotBefore().toInstant())) {
            throw invalid(ValidationReasons.CERT_NOT_YET_VALID, "гэрчилгээ хүчинтэй болоогүй байна (serial " + c.serial.toString(16) + ")");
        }
        if (now.minus(skew).isAfter(c.x509.getNotAfter().toInstant())) {
            throw invalid(ValidationReasons.CERT_EXPIRED, "гэрчилгээний хугацаа дууссан (serial " + c.serial.toString(16) + ")");
        }
    }

    /**
     * Purpose, trust anchor, chain, issuer (validity checked by the caller). Without an anchor the chain is skipped only
     * with allowUntrusted; an explicit issuer allowlist is still checked then (TS {@code verifyCertificate}).
     */
    private void verifyCertificate(Cert leaf, String protocol, Instant now) {
        checkPurpose(leaf, protocol);
        if (anchors.isEmpty()) {
            if (!allowUntrusted) {
                throw invalid(ValidationReasons.TRUST_NO_ANCHOR,
                    "trust anchor тохируулаагүй — итгэлцэл шалгах боломжгүй (production-д TrustAnchorsPEM өг, эсвэл AllowUntrusted)");
            }
        } else {
            verifyChain(leaf, now, PROTOCOL_ACSP_V2.equals(protocol) ? EKU_CLIENT_AUTH : EKU_EMAIL_PROTECTION);
        }
        checkIssuer(leaf);
    }

    private static boolean ku(Cert c, int bit) {
        boolean[] k = c.x509.getKeyUsage();
        return k != null && bit < k.length && k[bit];
    }

    /**
     * Go {@code checkPurpose} (CA crypto/ca_profile.go): ACSP_V2 (auth) → KU digitalSignature + EKU clientAuth (or any);
     * RAW_DIGEST_SIGNATURE (sign) → KU contentCommitment.
     */
    private void checkPurpose(Cert leaf, String protocol) {
        if (!checkKeyUsage) return;
        if (PROTOCOL_ACSP_V2.equals(protocol)) {
            if (!ku(leaf, KU_DIGITAL_SIGNATURE)) {
                throw invalid(ValidationReasons.PURPOSE_AUTH_DIGITAL_SIGNATURE, "нэвтрэлтийн гэрчилгээнд KeyUsage digitalSignature алга");
            }
            List<String> eku = leaf.extKeyUsage();
            if (!eku.contains(EKU_CLIENT_AUTH) && !eku.contains(EKU_ANY)) {
                throw invalid(ValidationReasons.PURPOSE_AUTH_CLIENT_AUTH,
                    "нэвтрэлтийн гэрчилгээнд ExtKeyUsage clientAuth алга (гарын үсгийн гэрчилгээ байж болзошгүй)");
            }
            return;
        }
        if (!ku(leaf, KU_NON_REPUDIATION)) {
            throw invalid(ValidationReasons.PURPOSE_SIGN_NON_REPUDIATION, "гарын үсгийн гэрчилгээнд KeyUsage nonRepudiation (contentCommitment) алга");
        }
    }

    /** Go {@code checkIssuer}: the direct issuer's SKI (else the leaf's AKI) must be allowed. */
    private void checkIssuer(Cert leaf) {
        if (allowedIssuers == null) return;
        byte[] ski = leaf.authorityKeyId();
        Cert is = findIssuer(leaf);
        if (is != null && is.subjectKeyId().length > 0) ski = is.subjectKeyId();
        if (ski.length == 0 || !allowedIssuers.contains(Text.hex(ski))) {
            throw invalid(ValidationReasons.ISSUER_NOT_ALLOWED, "гэрчилгээг гаргасан CA зөвшөөрөгдсөн иргэний issuer биш (allowedIssuerSkis)");
        }
    }

    /** Go {@code issuedBy}: parent is a CA, names match, AKI = SKI when both present, parent's signature (CheckSignatureFrom). */
    private static boolean issuedBy(Cert child, Cert parent) {
        if (!parent.isCa() || !Arrays.equals(child.rawIssuer, parent.rawSubject)) return false;
        byte[] aki = child.authorityKeyId();
        byte[] ski = parent.subjectKeyId();
        if (aki.length > 0 && ski.length > 0 && !Arrays.equals(aki, ski)) return false;
        return parent.mayIssue(KU_KEY_CERT_SIGN) && child.signedBy(parent);
    }

    /** Go {@code findIssuer}: the leaf's direct issuer from the trust pool (intermediates first), or null. */
    private Cert findIssuer(Cert leaf) {
        List<Cert> pool = new ArrayList<>(intermediates);
        pool.addAll(anchors);
        for (Cert c : pool) if (issuedBy(leaf, c)) return c;
        return null;
    }

    /** Go {@code checkLevel}: ADVANCED &lt; QUALIFIED &lt; QSCD; a higher level than required is accepted. */
    private void checkLevel(CertificateLevel level) {
        if (LEVEL_RANK.get(level.name()) < LEVEL_RANK.get(requiredLevel.name())) {
            throw invalid(ValidationReasons.LEVEL_INSUFFICIENT, "гэрчилгээний түвшин хүрэлцэхгүй: " + level + " < " + requiredLevel);
        }
    }

    /**
     * Go {@code effectiveLevel}: a response level above the certificate's → {@link ValidationReasons#LEVEL_CLAIMED_HIGHER}
     * (forged / proxied response); a lower one is taken; missing / unknown → the certificate's.
     */
    private static CertificateLevel effectiveLevel(String claimed, CertificateLevel fromCert) {
        Integer c = claimed == null ? null : LEVEL_RANK.get(claimed);
        if (c == null) return fromCert;
        if (c > LEVEL_RANK.get(fromCert.name())) {
            throw invalid(ValidationReasons.LEVEL_CLAIMED_HIGHER, "хариуны certificateLevel " + claimed + " гэрчилгээнээс (" + fromCert + ") өндөр");
        }
        return CertificateLevel.valueOf(claimed);
    }

    /**
     * The level a certificate supports (Go {@code CertificateLevelOf}, TS {@code certificateLevelOf}; CA
     * crypto/ca_profile.go): qcStatements with QcCompliance → QUALIFIED (+ QcSSCD → QSCD), without QcCompliance →
     * ADVANCED; no qcStatements → a signing certificate is ADVANCED (USB tokens issued before 2026-11-06), an
     * authentication certificate (the CA writes no qcStatements into AUTH) is QUALIFIED by profile — KeyUsage
     * keyEncipherment (phone P-CITIZEN-AUTH) or EKU clientAuth + emailProtection with the national policy
     * 2.16.496.1.101.1.2.8 (token P-CITIZEN-AUTH-TOKEN, EC) — else ADVANCED.
     *
     * @param protocol {@link #PROTOCOL_ACSP_V2} (auth) or {@link #PROTOCOL_RAW_DIGEST} (sign)
     * @throws EidException.Validation qcStatements malformed ({@link ValidationReasons#LEVEL_QC_MALFORMED})
     */
    public static CertificateLevel certificateLevelOf(X509Certificate cert, String protocol) {
        if (cert == null) throw invalid(ValidationReasons.CERT_MALFORMED, "гэрчилгээ алга");
        Cert c;
        try {
            c = Cert.parse(cert.getEncoded());
        } catch (CertificateEncodingException | IllegalArgumentException e) {
            throw invalid(ValidationReasons.CERT_MALFORMED, "гэрчилгээ задарсангүй");
        }
        return certificateLevelOf(c, protocol);
    }

    static CertificateLevel certificateLevelOf(Cert c, String protocol) {
        byte[] v = c.extensionValue(OID_QC_STATEMENTS);
        if (v != null) {
            boolean compliance = false;
            boolean sscd = false;
            try {
                Der.Tlv seq = Der.parse(v);
                if (seq.tag != Der.SEQUENCE || seq.end != v.length) throw new IllegalArgumentException("qcStatements");
                for (Der.Tlv st : seq.children()) {
                    if (st.tag != Der.SEQUENCE) throw new IllegalArgumentException("qcStatement");
                    List<Der.Tlv> f = st.children();
                    if (f.isEmpty() || f.get(0).tag != Der.OID) throw new IllegalArgumentException("statementId");
                    String id = f.get(0).oid();
                    compliance |= id.equals(OID_QC_COMPLIANCE);
                    sscd |= id.equals(OID_QC_SSCD);
                }
            } catch (RuntimeException e) {
                throw invalid(ValidationReasons.LEVEL_QC_MALFORMED, "qcStatements буруу");
            }
            if (!compliance) return CertificateLevel.ADVANCED;
            return sscd ? CertificateLevel.QSCD : CertificateLevel.QUALIFIED;
        }
        if (PROTOCOL_ACSP_V2.equals(protocol) && (ku(c, KU_KEY_ENCIPHERMENT) || isCitizenAuthToken(c))) return CertificateLevel.QUALIFIED;
        return CertificateLevel.ADVANCED;
    }

    /** P-CITIZEN-AUTH-TOKEN: EKU clientAuth + emailProtection and the national policy OID. */
    private static boolean isCitizenAuthToken(Cert c) {
        List<String> eku = c.extKeyUsage();
        if (!eku.contains(EKU_CLIENT_AUTH) || !eku.contains(EKU_EMAIL_PROTECTION)) return false;
        try {
            return c.policyIdentifiers().contains(OID_POLICY_NATIONAL);
        } catch (RuntimeException e) {
            return false;
        }
    }

    /**
     * Go {@code algorithmOf}: the response's signatureAlgorithm + hash against what the RP asked for and the key type
     * (downgrade / algorithm-confusion guard). ECDSA: the CA's ECDSA credential signs SHA-256 only — ecdsa-with-SHA256,
     * EC P-256, wanted hash SHA-256. RSA names need an RSA key and the exact wanted hash. Returns {alg, hash}.
     */
    private static String[] algorithmOf(SessionResult r, PublicKey pub, String wantAlg, String wantHash) {
        String alg = nz(r.signatureAlgorithm());
        boolean isRsa = pub instanceof RSAPublicKey;
        boolean isEc = pub instanceof ECPublicKey;
        String hash;
        if (alg.equals(SignatureAlgorithm.RSASSA_PSS.wireName())) {
            if (!isRsa) throw invalid(ValidationReasons.ALG_KEY_MISMATCH, "rsassa-pss нь RSA бус гэрчилгээтэй");
            SignatureAlgorithmParameters p = r.signatureAlgorithmParameters();
            hash = p == null ? "" : nz(p.hashAlgorithm());
            int hLen = Prehashed.hashLen(hash);
            if (hLen == 0) throw invalid(ValidationReasons.ALG_UNSUPPORTED, "дэмжигдээгүй hashAlgorithm: " + hash);
            if (!nz(p.maskGenHashAlgorithm()).isEmpty() && !nz(p.maskGenHashAlgorithm()).equals(hash)) {
                throw invalid(ValidationReasons.ALG_MGF1, "MGF1 hash нь hashAlgorithm-аас өөр");
            }
            if (p.saltLength() != null && p.saltLength() != hLen) throw invalid(ValidationReasons.ALG_SALT_LENGTH, "saltLength ≠ hLen");
        } else if (alg.equals(SignatureAlgorithm.SHA256_WITH_RSA.wireName()) || alg.equals(SignatureAlgorithm.SHA384_WITH_RSA.wireName())
            || alg.equals(SignatureAlgorithm.SHA512_WITH_RSA.wireName())) {
            if (!isRsa) throw invalid(ValidationReasons.ALG_KEY_MISMATCH, alg + " нь RSA бус гэрчилгээтэй");
            hash = "SHA-" + alg.substring(3, 6);
        } else if (alg.equals(SignatureAlgorithm.ECDSA_WITH_SHA256.wireName())) {
            if (!isEc || !Prehashed.isP256(pub)) throw invalid(ValidationReasons.ALG_KEY_MISMATCH, alg + " нь EC P-256 бус гэрчилгээтэй");
            hash = HashAlgorithm.SHA_256.wireName();
            if (!wantHash.equals(hash)) {
                // The CA's ECDSA credential signs nothing but SHA-256 — the server cannot produce such a response.
                throw invalid(ValidationReasons.ALG_ECDSA_HASH, "ecdsa-with-SHA256 хариу " + wantHash
                    + " хүссэн session-д боломжгүй (ECDSA credential зөвхөн SHA-256)");
            }
        } else {
            throw invalid(ValidationReasons.ALG_UNSUPPORTED, "дэмжигдээгүй signatureAlgorithm: " + alg);
        }
        if (!wantAlg.isEmpty() && !alg.equals(wantAlg) && !alg.equals(SignatureAlgorithm.ECDSA_WITH_SHA256.wireName())) {
            throw invalid(ValidationReasons.ALG_MISMATCH, "signatureAlgorithm " + alg + " ≠ хүссэн " + wantAlg);
        }
        if (!hash.equals(wantHash)) throw invalid(ValidationReasons.ALG_HASH_MISMATCH, "hashAlgorithm " + hash + " ≠ хүссэн " + wantHash);
        return new String[] {alg, hash};
    }

    /**
     * The ACSP_V2 payload's initialCallbackUrl (Go {@code SignedCallbackURL}, TS {@code signedCallbackUrl}), decided by the
     * flow (Smart-ID: QR / Notification → "", Web2App / App2App → the RP's callback). The response's value
     * (signature.initialCallbackUrl) is used only when it is "" or byte-identical to the RP's callback; Web2App / App2App
     * require the RP's callback. Field absent (older CA; null) → the RP's callback.
     *
     * @throws EidException.Validation {@link ValidationReasons#AUTH_CALLBACK_URL}
     */
    public static String signedCallbackUrl(String fromResponse, String rpCallback, String flowType) {
        String rp = rpCallback == null ? "" : rpCallback;
        if (fromResponse == null) return rp;
        if (!fromResponse.isEmpty() && !fromResponse.equals(rp)) {
            throw invalid(ValidationReasons.AUTH_CALLBACK_URL,
                "signature.initialCallbackUrl нь хоосон ч биш, илгээсэн callback ч биш (хуурамч хариу байж болзошгүй)");
        }
        if ((FlowType.WEB2APP.wireName().equals(flowType) || FlowType.APP2APP.wireName().equals(flowType)) && !fromResponse.equals(rp)) {
            throw invalid(ValidationReasons.AUTH_CALLBACK_URL, flowType + " урсгалд signature.initialCallbackUrl нь илгээсэн callback байх ёстой");
        }
        return fromResponse;
    }

    // ── chain (TS validator.ts verifyChain / caReason / criticalReason / ekuReason) ──

    /** A chain failure: reason key + prose. */
    private static final class Bad {
        final String key;
        final String msg;

        Bad(String key, String msg) {
            this.key = key;
            this.msg = msg;
        }
    }

    /**
     * RFC 5280 path validation by a deterministic hand-written builder (TS {@code verifyChain}): the path from the leaf to
     * a trust anchor is assembled from the intermediates / anchors with backtracking; every issuer: subject =
     * child.issuer, AKI = SKI (when both present), signature, CA (basicConstraints CA:TRUE), keyCertSign when KeyUsage is
     * present, pathLenConstraint (intermediate CAs below it), validity, EKU (if present) containing the usage or
     * anyExtendedKeyUsage. The leaf and every CA: an unknown critical extension → rejected; a CA with nameConstraints →
     * rejected (fail-closed — the SDKs cannot evaluate them identically; the real chain 01–04 has none). If several paths
     * exist, any fully valid one succeeds. Time = now clamped into the leaf's validity (within the clock skew; the leaf
     * itself was checked by checkValidity). Certificate policies are not evaluated.
     */
    private void verifyChain(Cert leaf, Instant at, String usage) {
        Instant from = leaf.x509.getNotBefore().toInstant();
        Instant to = leaf.x509.getNotAfter().toInstant();
        Instant now = at.isBefore(from) ? from : at.isAfter(to) ? to : at;
        Bad leafBad = criticalReason(leaf);
        if (leafBad == null) leafBad = ekuReason(leaf, usage);
        if (leafBad != null) throw invalid(leafBad.key, "гэрчилгээний гинж хүчингүй: " + leafBad.msg);
        Bad[] reason = new Bad[1];
        if (extend(leaf, new ArrayList<>(), now, usage, reason)) return;
        if (reason[0] != null) throw invalid(reason[0].key, "гэрчилгээний гинж хүчингүй: " + reason[0].msg);
        throw invalid(ValidationReasons.CHAIN_UNTRUSTED, "гэрчилгээний итгэлцлийн гинж trust anchor (Root CA) хүрсэнгүй");
    }

    private boolean extend(Cert cur, List<Cert> cas, Instant now, String usage, Bad[] reason) {
        if (cas.size() >= MAX_PATH) return false;
        int n = anchors.size() + intermediates.size();
        for (int i = 0; i < n; i++) {
            boolean isAnchor = i < anchors.size();
            Cert cand = isAnchor ? anchors.get(i) : intermediates.get(i - anchors.size());
            if (containsSame(cas, cand) || !signedBy(cur, cand, reason)) continue;
            Bad bad = caReason(cand, cas.size(), now, usage);
            if (bad != null) {
                if (reason[0] == null) reason[0] = bad;
                continue;
            }
            if (isAnchor) return true;
            cas.add(cand);
            if (extend(cand, cas, now, usage, reason)) return true;
            cas.remove(cas.size() - 1);
        }
        return false;
    }

    private static boolean containsSame(List<Cert> l, Cert c) {
        for (Cert x : l) if (x == c) return true;
        return false;
    }

    /**
     * child issued by cand: issuer name = subject (DER), AKI = SKI when both present, signature (TS {@code signedBy}) by
     * a chain algorithm — SHA-256/384/512 with RSA PKCS#1 v1.5, RSASSA-PSS or ECDSA (Go x509 rejects SHA-1 / MD5 chains);
     * a matching issuer with a weaker algorithm is recorded as the chain reason.
     */
    private static boolean signedBy(Cert child, Cert cand, Bad[] reason) {
        if (!Arrays.equals(child.rawIssuer, cand.rawSubject)) return false;
        byte[] aki = child.authorityKeyId();
        byte[] ski = cand.subjectKeyId();
        if (aki.length > 0 && ski.length > 0 && !Arrays.equals(aki, ski)) return false;
        if (!child.strongSignatureAlgorithm()) {
            if (reason[0] == null) {
                reason[0] = new Bad(ValidationReasons.CHAIN_UNTRUSTED, "гарын үсгийн алгоритм зөвшөөрөгдөөгүй (SHA-1 / MD5; зөвхөн SHA-2 RSA, RSASSA-PSS, ECDSA)");
            }
            return false;
        }
        return child.signedBy(cand);
    }

    private static Bad criticalReason(Cert c) {
        for (String oid : c.criticalExtensionOids()) {
            if (!HANDLED_CRITICAL.contains(oid)) return new Bad(ValidationReasons.CHAIN_CRITICAL_EXTENSION, "үл таних critical extension");
        }
        return null;
    }

    /** EKU present → must contain the usage or anyExtendedKeyUsage (no EKU = any). */
    private static Bad ekuReason(Cert c, String usage) {
        List<String> eku = c.extKeyUsage();
        if (!eku.isEmpty() && !eku.contains(usage) && !eku.contains(EKU_ANY)) {
            return new Bad(ValidationReasons.CHAIN_EKU, "гэрчилгээний ExtKeyUsage энэ үйлдэлд тохирохгүй (гинжийн EKU)");
        }
        return null;
    }

    /** TS {@code caReason}: the issuer CA's checks; below = intermediate CAs under it (the leaf not counted). */
    private static Bad caReason(Cert ca, int below, Instant now, String usage) {
        if (!ca.isCa()) return new Bad(ValidationReasons.CHAIN_NOT_CA, "завсрын гэрчилгээ CA биш эсвэл keyCertSign эрхгүй");
        if (ca.isRsa() && ca.rsaBits() < MIN_RSA_BITS) return new Bad(ValidationReasons.CHAIN_UNTRUSTED, "CA-ийн RSA түлхүүр 2048 битээс бага");
        if (ca.extensionValue(OID_KEY_USAGE) != null && !ku(ca, KU_KEY_CERT_SIGN)) {
            return new Bad(ValidationReasons.CHAIN_NOT_CA, "CA-ийн KeyUsage-д keyCertSign алга");
        }
        if (now.isBefore(ca.x509.getNotBefore().toInstant()) || now.isAfter(ca.x509.getNotAfter().toInstant())) {
            return new Bad(ValidationReasons.CHAIN_EXPIRED, "гинжийн гэрчилгээний хугацаа дууссан эсвэл хүчинтэй болоогүй");
        }
        Integer pathLen = ca.maxPathLen();
        if (pathLen != null && below > pathLen) return new Bad(ValidationReasons.CHAIN_PATH_LEN, "pathLenConstraint зөрчсөн (завсрын CA хэт олон)");
        if (ca.extensionValue(OID_NAME_CONSTRAINTS) != null) {
            return new Bad(ValidationReasons.CHAIN_NAME_CONSTRAINTS, "CA-д name constraints байна (SDK үнэлдэггүй — fail-closed)");
        }
        Bad c = criticalReason(ca);
        return c != null ? c : ekuReason(ca, usage);
    }
}
