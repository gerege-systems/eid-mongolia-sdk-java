package mn.eidmongolia.eid;

import java.time.Instant;

/**
 * {@link DeviceLink#build} input (Go {@code DeviceLinkInput}, TS {@code BuildDeviceLinkInput}). Immutable; create with
 * {@link #builder()} or {@link DeviceLinkSession#linkInput}. String fields default to "".
 */
public final class DeviceLinkInput {
    final String deviceLinkBase;
    final DeviceLinkType deviceLinkType;
    final String sessionToken;
    final String sessionSecret;
    final DeviceLinkSessionType sessionType;
    final String lang;
    final Instant receivedAt;
    final Instant now;
    final String rpChallenge;
    final String digest;
    final String relyingPartyName;
    final String interactions;
    final String initialCallbackUrl;
    final String schemeName;
    final String brokeredRpName;

    private DeviceLinkInput(Builder b) {
        deviceLinkBase = b.deviceLinkBase;
        deviceLinkType = b.deviceLinkType;
        sessionToken = b.sessionToken;
        sessionSecret = b.sessionSecret;
        sessionType = b.sessionType;
        lang = b.lang;
        receivedAt = b.receivedAt;
        now = b.now;
        rpChallenge = b.rpChallenge;
        digest = b.digest;
        relyingPartyName = b.relyingPartyName;
        interactions = b.interactions;
        initialCallbackUrl = b.initialCallbackUrl;
        schemeName = b.schemeName;
        brokeredRpName = b.brokeredRpName;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A builder pre-filled with this input's values. */
    public Builder toBuilder() {
        return new Builder().deviceLinkBase(deviceLinkBase).deviceLinkType(deviceLinkType).sessionToken(sessionToken)
            .sessionSecret(sessionSecret).sessionType(sessionType).lang(lang).receivedAt(receivedAt).now(now)
            .rpChallenge(rpChallenge).digest(digest).relyingPartyName(relyingPartyName).interactions(interactions)
            .initialCallbackUrl(initialCallbackUrl).schemeName(schemeName).brokeredRpName(brokeredRpName);
    }

    /** No secret in the text. */
    @Override
    public String toString() {
        return "DeviceLinkInput[" + deviceLinkType + ", " + sessionType + ", base=" + deviceLinkBase + "]";
    }

    public static final class Builder {
        private String deviceLinkBase = "";
        private DeviceLinkType deviceLinkType;
        private String sessionToken = "";
        private String sessionSecret = "";
        private DeviceLinkSessionType sessionType;
        private String lang = "";
        private Instant receivedAt;
        private Instant now;
        private String rpChallenge = "";
        private String digest = "";
        private String relyingPartyName = "";
        private String interactions = "";
        private String initialCallbackUrl = "";
        private String schemeName = "";
        private String brokeredRpName = "";

        private Builder() {
        }

        private static String s(String v) {
            return v == null ? "" : v;
        }

        /** The start response's deviceLinkBase (e.g. https://ca.eidmongolia.mn/dl). */
        public Builder deviceLinkBase(String v) {
            deviceLinkBase = s(v);
            return this;
        }

        public Builder deviceLinkType(DeviceLinkType v) {
            deviceLinkType = v;
            return this;
        }

        /** The start response's sessionToken, EXACTLY as received. */
        public Builder sessionToken(String v) {
            sessionToken = s(v);
            return this;
        }

        /** The start response's sessionSecret (standard base64, padded). Backend only. */
        public Builder sessionSecret(String v) {
            sessionSecret = s(v);
            return this;
        }

        public Builder sessionType(DeviceLinkSessionType v) {
            sessionType = v;
            return this;
        }

        /** ISO 639-2, three lower-case letters (mon, eng) — the /dl fallback page language. */
        public Builder lang(String v) {
            lang = s(v);
            return this;
        }

        /** When the RP backend received the start response. Required for QR. */
        public Builder receivedAt(Instant v) {
            receivedAt = v;
            return this;
        }

        /** The current time (tests). null = {@link Instant#now()}. */
        public Builder now(Instant v) {
            now = v;
            return this;
        }

        /** auth: the rpChallenge sent (its base64 text). */
        public Builder rpChallenge(String v) {
            rpChallenge = s(v);
            return this;
        }

        /** sign: the digest sent (base64 text). */
        public Builder digest(String v) {
            digest = s(v);
            return this;
        }

        /** EXACTLY the relyingPartyName sent in the start request. */
        public Builder relyingPartyName(String v) {
            relyingPartyName = s(v);
            return this;
        }

        /** auth/sign: the interactions base64 STRING sent; cert: "". */
        public Builder interactions(String v) {
            interactions = s(v);
            return this;
        }

        /** The raw initialCallbackUrl sent. Required for Web2App/App2App; NOT part of the QR authCode. */
        public Builder initialCallbackUrl(String v) {
            initialCallbackUrl = s(v);
            return this;
        }

        /** "" = "smart-id". */
        public Builder schemeName(String v) {
            schemeName = s(v);
            return this;
        }

        /** eID has no broker: "". */
        public Builder brokeredRpName(String v) {
            brokeredRpName = s(v);
            return this;
        }

        public DeviceLinkInput build() {
            return new DeviceLinkInput(this);
        }
    }
}
