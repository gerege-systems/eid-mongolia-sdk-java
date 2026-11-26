package mn.eidmongolia.eid;

import java.time.Duration;

/**
 * {@link SealService#waitForCertificate} / {@link SealService#waitForGrant} options (Go {@code SealWaitOptions}).
 *
 * @param timeout the total wait; null / ≤ 0 = {@link SealService#DEFAULT_WAIT_TIMEOUT}
 * @param interval between polls; null / ≤ 0 = {@link SealService#DEFAULT_POLL_INTERVAL} (a longer 429/503 Retry-After wins)
 */
public record SealWaitOptions(Duration timeout, Duration interval) {
}
