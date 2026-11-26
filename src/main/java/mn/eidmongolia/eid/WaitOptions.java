package mn.eidmongolia.eid;

import java.time.Duration;
import java.time.Instant;

/** {@link SessionService#waitForResult} settings (Go {@code WaitOptions}). Create with {@link #builder()}. */
public final class WaitOptions {
    static final WaitOptions DEFAULTS = builder().build();

    final Duration maxWait;
    final Instant expiresAt;
    final Duration serverPoll;

    private WaitOptions(Builder b) {
        maxWait = b.maxWait;
        expiresAt = b.expiresAt;
        serverPoll = b.serverPoll;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Duration maxWait;
        private Instant expiresAt;
        private Duration serverPoll;

        private Builder() {
        }

        /**
         * The total wait. null / ≤ 0: {@link #expiresAt} + {@link SessionService#WAIT_GRACE}; without expiresAt the
         * discovery sessionTtl (max(auth, sign)) + grace; when that is unknown too {@link SessionService#DEFAULT_MAX_WAIT}.
         * When set, only this counts.
         */
        public Builder maxWait(Duration v) {
            maxWait = v;
            return this;
        }

        /** The start response's expiresAt ({@link NotificationSession#expiresAt()}); with it discovery is not fetched. */
        public Builder expiresAt(Instant v) {
            expiresAt = v;
            return this;
        }

        /** One long-poll. null / ≤ 0 = {@link SessionService#DEFAULT_SERVER_POLL}. */
        public Builder serverPoll(Duration v) {
            serverPoll = v;
            return this;
        }

        public WaitOptions build() {
            return new WaitOptions(this);
        }
    }
}
