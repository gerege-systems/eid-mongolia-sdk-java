package mn.eidmongolia.eid;

/**
 * The stable reason keys of {@link EidException.Validation#reason()} — the keys of the cross-SDK conformance corpus
 * ({@code rp-conformance/1}, Go {@code testdata/conformance/README.md} §rp-validate). The validator performs its checks
 * in the order listed there and stops at the first failure. Messages stay prose (Mongolian, like the Go/TS SDKs); branch
 * on these keys, never on the message.
 */
public final class ValidationReasons {
    private ValidationReasons() {
    }

    /** state ≠ COMPLETE (or no result at all). endResult ≠ OK is {@link EidException.SessionFailed}, not this. */
    public static final String SESSION_NOT_COMPLETE = "session.not_complete";
    /** signatureProtocol present and ≠ ACSP_V2 (auth) / RAW_DIGEST_SIGNATURE (sign). */
    public static final String PROTOCOL_MISMATCH = "protocol.mismatch";
    public static final String NO_CERTIFICATE = "response.no_certificate";
    public static final String NO_SIGNATURE = "response.no_signature";
    public static final String NO_DOCUMENT_NUMBER = "response.no_document_number";
    /** The certificate is not base64 DER X.509. */
    public static final String CERT_MALFORMED = "cert.malformed";
    public static final String CERT_NOT_YET_VALID = "cert.not_yet_valid";
    public static final String CERT_EXPIRED = "cert.expired";
    /** Auth leaf without KeyUsage digitalSignature. */
    public static final String PURPOSE_AUTH_DIGITAL_SIGNATURE = "purpose.auth_digital_signature";
    /** Auth leaf without EKU clientAuth (or anyExtendedKeyUsage). */
    public static final String PURPOSE_AUTH_CLIENT_AUTH = "purpose.auth_client_auth";
    /** Sign / certificate-choice leaf without KeyUsage nonRepudiation (contentCommitment). */
    public static final String PURPOSE_SIGN_NON_REPUDIATION = "purpose.sign_non_repudiation";
    /** No trust anchor configured (and allowUntrusted off). */
    public static final String TRUST_NO_ANCHOR = "trust.no_anchor";
    /** The leaf or a chain CA has a critical extension the SDK does not handle. */
    public static final String CHAIN_CRITICAL_EXTENSION = "chain.critical_extension";
    /** A CA on the path (anchor included) carries nameConstraints — rejected, satisfied or not (fail-closed). */
    public static final String CHAIN_NAME_CONSTRAINTS = "chain.name_constraints";
    public static final String CHAIN_PATH_LEN = "chain.path_len";
    /** The leaf's or a CA's EKU lacks the purpose (auth → clientAuth, sign → emailProtection) and anyExtendedKeyUsage. */
    public static final String CHAIN_EKU = "chain.eku";
    /** An issuer is not CA:TRUE or its KeyUsage lacks keyCertSign. */
    public static final String CHAIN_NOT_CA = "chain.not_ca";
    /** A CA is outside its validity at the chain time. */
    public static final String CHAIN_EXPIRED = "chain.expired";
    /** No path from the leaf to a trust anchor. */
    public static final String CHAIN_UNTRUSTED = "chain.untrusted";
    /** The direct issuer's SKI is not in the allowed issuer list. */
    public static final String ISSUER_NOT_ALLOWED = "issuer.not_allowed";
    /** qcStatements is not a SEQUENCE OF SEQUENCE { OID, … }. */
    public static final String LEVEL_QC_MALFORMED = "level.qc_malformed";
    /** The response claims a higher certificateLevel than the certificate supports. */
    public static final String LEVEL_CLAIMED_HIGHER = "level.claimed_higher";
    /** The effective level is below the required level. */
    public static final String LEVEL_INSUFFICIENT = "level.insufficient";
    /** No ACSP context given to validateAuth (Java/Go API misuse; not a corpus key). */
    public static final String AUTH_ACSP_MISSING = "auth.acsp_missing";
    public static final String AUTH_SERVER_RANDOM = "auth.server_random";
    public static final String AUTH_USER_CHALLENGE = "auth.user_challenge";
    /** The signed flowType is not one of the flows the RP offered. */
    public static final String AUTH_FLOW_NOT_OFFERED = "auth.flow_not_offered";
    /** The signed flowType differs from the expected flow (relay protection; auth and sign). */
    public static final String FLOW_MISMATCH = "flow.mismatch";
    public static final String AUTH_VERIFIER_REQUIRED = "auth.verifier_required";
    public static final String AUTH_VERIFIER_MISMATCH = "auth.verifier_mismatch";
    public static final String AUTH_INTERACTION_TYPE_MISSING = "auth.interaction_type_missing";
    /** The response's certificate differs from the expected (certificate-choice) one. */
    public static final String SIGN_CERTIFICATE_MISMATCH = "sign.certificate_mismatch";
    /** The digest given to validateSign is not base64 (Go-only key, not in the corpus table). */
    public static final String SIGN_DIGEST_BASE64 = "sign.digest_base64";
    /** Unknown signatureAlgorithm or hash. */
    public static final String ALG_UNSUPPORTED = "alg.unsupported";
    /** Algorithm family does not match the key. */
    public static final String ALG_KEY_MISMATCH = "alg.key_mismatch";
    public static final String ALG_MGF1 = "alg.mgf1";
    public static final String ALG_SALT_LENGTH = "alg.salt_length";
    /** ecdsa-with-SHA256 answering a session whose hash is not SHA-256. */
    public static final String ALG_ECDSA_HASH = "alg.ecdsa_hash";
    /** Response algorithm ≠ the requested one (downgrade). */
    public static final String ALG_MISMATCH = "alg.mismatch";
    /** Response hash ≠ the requested one. */
    public static final String ALG_HASH_MISMATCH = "alg.hash_mismatch";
    /** signature.initialCallbackUrl is neither "" nor the RP's callback (or not the callback for Web2App/App2App). */
    public static final String AUTH_CALLBACK_URL = "auth.callback_url";
    /** The ACSP_V2 signature does not verify. */
    public static final String AUTH_SIGNATURE = "auth.signature";
    public static final String SIGN_DIGEST_LENGTH = "sign.digest_length";
    /** The prehashed signature over the digest does not verify. */
    public static final String SIGN_SIGNATURE = "sign.signature";
    /** Revocation: the certificate is revoked (an OCSP «unknown» counts as revoked). */
    public static final String REVOCATION_REVOKED = "revocation.revoked";
    /** Revocation: no answer and the mode is hard-fail. */
    public static final String REVOCATION_UNKNOWN = "revocation.unknown";

    // ── Java-only keys (not in rp-conformance/1; the Go / TS SDKs return prose ValidationError reasons here) ──

    /**
     * The certificate subject has more than one SERIALNUMBER or more than one CN — the identity would depend on which
     * one a parser picks (cross-SDK hardening, rejected before any other certificate check).
     */
    public static final String CERT_SUBJECT_AMBIGUOUS = "cert.subject_ambiguous";
    /** A seal / seal-request / seal-grant response lacks a required member or does not decode. */
    public static final String SEAL_RESPONSE = "seal.response";
    /** The seal response's certificate is not an e-Seal certificate (KeyUsage = nonRepudiation only, no EKU). */
    public static final String SEAL_NOT_ESEAL = "seal.not_eseal";
    /** The seal signature does not verify over the digest with the response's certificate. */
    public static final String SEAL_SIGNATURE = "seal.signature";
    /** Token: the CA's csrAuthSha256 / csrSignSha256 differ from the CSRs sent, or a dryRun answer was not a dry run. */
    public static final String TOKEN_RESPONSE = "token.response";
    /** Token: an issued certificate does not decode or its key differs from the CSR's (do not write it to the token). */
    public static final String TOKEN_CERTIFICATE = "token.certificate";
    /** Token auth: the challenge is bound to another RP (rpUUID), or rpUUID / challenge are malformed. */
    public static final String TOKEN_CHALLENGE = "token.challenge";
    /** Token auth: the raw r‖s signature does not verify over the token-auth digest (EC P-256). */
    public static final String TOKEN_SIGNATURE = "token.signature";
    /** Token auth: the CA did not answer endResult OK, or identity.etsi is not the certificate's SERIALNUMBER. */
    public static final String TOKEN_RESULT = "token.result";
}
