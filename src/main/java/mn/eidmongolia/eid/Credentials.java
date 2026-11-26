package mn.eidmongolia.eid;

import java.util.Objects;

/**
 * The RP's identity and API secret (Go {@code Credentials}).
 *
 * @param rpUuid the registered RP UUID (relyingPartyUUID)
 * @param rpName the subsystem name shown on the citizen's phone (e.g. «Интернэт банк»), ≤ 120 characters
 * @param apiSecret rp_sk_… — backend only; {@link #toString()} never prints it
 */
public record Credentials(String rpUuid, String rpName, String apiSecret) {
    public Credentials {
        Objects.requireNonNull(rpUuid, "rpUuid");
        Objects.requireNonNull(rpName, "rpName");
        Objects.requireNonNull(apiSecret, "apiSecret");
    }

    @Override
    public String toString() {
        return "Credentials[rpUuid=" + rpUuid + ", rpName=" + rpName + ", apiSecret=***]";
    }
}
