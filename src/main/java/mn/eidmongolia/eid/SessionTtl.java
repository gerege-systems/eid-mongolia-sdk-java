package mn.eidmongolia.eid;

import java.time.Duration;

/**
 * Discovery ({@code /.well-known/eid}) {@code sessionTtl}: the CA's live authentication / signature session lifetime
 * (Go {@code SessionTTL}). {@link Duration#ZERO} when the CA does not publish it.
 */
public record SessionTtl(Duration auth, Duration sign) {
}
