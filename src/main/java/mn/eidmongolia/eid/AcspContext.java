package mn.eidmongolia.eid;

import java.util.List;

/**
 * The ACSP_V2 context of an authentication session: the values the RP sent (Go {@code ACSPContext}). The validator
 * rebuilds the signed payload from this and the response. The SDK fills it when the session starts; the RP stores it
 * with the session on its server.
 *
 * @param interactions the base64 STRING sent (never re-serialised)
 * @param flowTypes the flows the RP offered; the response's flowType must be one of them
 */
public record AcspContext(String rpChallenge, String relyingPartyName, String brokeredRpName, String interactions,
    String initialCallbackUrl, List<FlowType> flowTypes, SignatureAlgorithm signatureAlgorithm, HashAlgorithm hashAlgorithm) {
    public AcspContext {
        flowTypes = flowTypes == null ? List.of() : List.copyOf(flowTypes);
    }
}
