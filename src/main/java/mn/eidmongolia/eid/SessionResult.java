package mn.eidmongolia.eid;

/**
 * A session poll result — the raw material for the validator (Go {@code SessionResult}). Absent string fields are "".
 *
 * @param certificateDerB64 the citizen's X.509 certificate (DER, base64)
 * @param signatureValueB64 the signature (base64)
 * @param serverRandom ACSP_V2: server random (base64)
 * @param userChallenge ACSP_V2: phone challenge (base64url)
 * @param initialCallbackUrl the initialCallbackUrl signed into the ACSP_V2 payload; null = field absent (older CA)
 * @param signatureAlgorithmParameters rsassa-pss parameters, null when absent
 * @param onBehalfOf the server-checked organisation; null = a natural person
 * @param person the COMPLETE+OK authentication person block; null when absent (not signed — see {@link Person})
 * @param tokenCertificate token certificate issuance block; null otherwise
 * @param presentationJws «My QR» presentation JWS (UNVERIFIED); null otherwise
 * @param rawJson the server's raw JSON
 */
public record SessionResult(String state, String endResult, String documentNumber, String certificateDerB64,
    String certificateLevel, String signatureValueB64, String signatureAlgorithm, String signatureProtocol,
    String serverRandom, String userChallenge, String flowType, String initialCallbackUrl,
    SignatureAlgorithmParameters signatureAlgorithmParameters, String interactionTypeUsed, OrgResult onBehalfOf,
    Person person, TokenCertSessionBlock tokenCertificate, String presentationJws, String rawJson) {

    public static final String STATE_RUNNING = "RUNNING";
    public static final String STATE_COMPLETE = "COMPLETE";

    public static final String END_RESULT_OK = "OK";
    public static final String END_RESULT_USER_REFUSED = "USER_REFUSED";
    public static final String END_RESULT_USER_REFUSED_DISPLAYTEXTANDPIN = "USER_REFUSED_DISPLAYTEXTANDPIN";
    public static final String END_RESULT_USER_REFUSED_VC_CHOICE = "USER_REFUSED_VC_CHOICE";
    public static final String END_RESULT_USER_REFUSED_CONFIRMATIONMESSAGE = "USER_REFUSED_CONFIRMATIONMESSAGE";
    public static final String END_RESULT_USER_REFUSED_CERT_CHOICE = "USER_REFUSED_CERT_CHOICE";
    public static final String END_RESULT_TIMEOUT = "TIMEOUT";
    public static final String END_RESULT_DOCUMENT_UNUSABLE = "DOCUMENT_UNUSABLE";
    public static final String END_RESULT_WRONG_VC = "WRONG_VC";
    public static final String END_RESULT_PROTOCOL_FAILURE = "PROTOCOL_FAILURE";
}
