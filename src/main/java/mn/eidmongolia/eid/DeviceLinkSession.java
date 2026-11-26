package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * A device-link (QR / Web2App / App2App) session (Go {@code DeviceLinkSession}). Keep {@code sessionToken} and
 * {@code sessionSecret} on the backend ONLY — never send them to a browser/app; {@link #toString()} omits the secret.
 *
 * @param deviceLinkBase the link base URL; build the link with {@link DeviceLink#build}
 * @param vc the 5-digit verification code (NOT a PIN), shown in the RP UI
 * @param receivedAt when the RP backend received the start response (source of the QR elapsedSeconds)
 * @param sessionType auth | sign | cert
 * @param sign signature sessions only
 * @param relyingPartyName the name sent in a certificate-choice request (cert authCode)
 * @param callbackUrl the raw initialCallbackUrl of a certificate-choice device-link request ("" = QR only)
 * @param expiresAt as in {@link NotificationSession#expiresAt()}
 */
public record DeviceLinkSession(String sessionId, String sessionToken, String sessionSecret, String deviceLinkBase,
    String vc, String rpChallenge, AcspContext acsp, Instant receivedAt, DeviceLinkSessionType sessionType,
    SignContext sign, String relyingPartyName, String callbackUrl, Instant expiresAt) {

    /**
     * The {@link DeviceLink#build} input from this session's values (Go {@code LinkInput}). {@code lang}: ISO 639-2
     * (mon, eng). Web2App/App2App need a session started with a callback URL.
     */
    public DeviceLinkInput.Builder linkInput(DeviceLinkType type, String lang) {
        DeviceLinkInput.Builder in = DeviceLinkInput.builder().deviceLinkBase(deviceLinkBase).deviceLinkType(type)
            .sessionToken(sessionToken).sessionSecret(sessionSecret).sessionType(sessionType).lang(lang)
            .receivedAt(receivedAt);
        if (sessionType == DeviceLinkSessionType.SIGN && sign != null) {
            in.digest(sign.digest()).relyingPartyName(sign.relyingPartyName()).interactions(sign.interactions())
                .initialCallbackUrl(sign.initialCallbackUrl());
        } else if (sessionType == DeviceLinkSessionType.CERT) {
            in.relyingPartyName(relyingPartyName).initialCallbackUrl(callbackUrl);
        } else if (acsp != null) { // auth (an older stored session may have no sessionType)
            in.sessionType(DeviceLinkSessionType.AUTH).rpChallenge(acsp.rpChallenge())
                .relyingPartyName(acsp.relyingPartyName()).interactions(acsp.interactions())
                .initialCallbackUrl(acsp.initialCallbackUrl());
        }
        return in;
    }

    @Override
    public String toString() {
        return "DeviceLinkSession[sessionId=" + sessionId + ", sessionType=" + sessionType + ", deviceLinkBase="
            + deviceLinkBase + ", expiresAt=" + expiresAt + ", sessionToken=***, sessionSecret=***]";
    }
}
