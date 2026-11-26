package mn.eidmongolia.eid;

/**
 * Every input of the ACSP_V2 payload (Smart-ID v3 §ACSP_V2 digest calculation; Go {@code ACSPV2Params}). null is
 * treated as "".
 *
 * @param schemeName null / "" = "smart-id"
 * @param serverRandom base64, from the response EXACTLY as received
 * @param rpChallenge base64, as the RP sent it
 * @param userChallenge base64url (43 characters), from the response
 * @param relyingPartyName the raw string sent in the request
 * @param brokeredRpName currently ""
 * @param interactions the base64 STRING sent in the request
 * @param initialCallbackUrl the raw string signed into the payload, "" when none
 */
public record AcspV2Params(String schemeName, String serverRandom, String rpChallenge, String userChallenge,
    String relyingPartyName, String brokeredRpName, String interactions, String interactionTypeUsed,
    String initialCallbackUrl, String flowType) {
}
