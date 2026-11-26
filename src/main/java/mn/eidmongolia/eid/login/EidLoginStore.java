package mn.eidmongolia.eid.login;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * The sign-in state store (Go {@code eidlogin.Store}, TS {@code EidLoginStore}). Default: {@link #memory()} (one
 * process); several instances need a shared store (Redis …). Implementations must be thread-safe, and
 * {@link #delete} atomic — it decides which concurrent request completes a sign-in (only one gets true).
 */
public interface EidLoginStore {
    /** The memory store's cap (active sign-ins). */
    int MEMORY_MAX = 10_000;

    /** null when absent or expired. */
    EidLoginTx get(String sessionId);

    /**
     * Stores (or replaces) the state for ttl.
     *
     * @throws StoreFullException the store is full — start answers 503 {"error":"busy"}
     */
    void set(EidLoginTx tx, Duration ttl);

    /** true when it existed (and is now gone). */
    boolean delete(String sessionId);

    /** Thrown by {@link #set} when the store is full. */
    final class StoreFullException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public StoreFullException() {
            super("eidlogin: memory store дүүрсэн");
        }
    }

    /**
     * A one-process memory store with TTL, at most {@link #MEMORY_MAX} entries (Go {@code NewMemoryStore}): when full it
     * drops expired entries and, if still full, refuses NEW sign-ins ({@link StoreFullException}) — started sign-ins
     * are never evicted.
     */
    static EidLoginStore memory() {
        return new Memory(MEMORY_MAX, Clock.systemUTC());
    }

    /** The memory store with another cap and clock (tests). */
    static EidLoginStore memory(int max, Clock clock) {
        return new Memory(max, clock);
    }

    /** Go {@code memoryStore}. */
    final class Memory implements EidLoginStore {
        private final Map<String, Object[]> m = new HashMap<>();
        private final int max;
        private final Clock clock;

        Memory(int max, Clock clock) {
            this.max = max;
            this.clock = clock;
        }

        @Override
        public synchronized EidLoginTx get(String k) {
            Object[] e = m.get(k);
            if (e == null) return null;
            if (!clock.instant().isBefore((Instant) e[1])) {
                m.remove(k);
                return null;
            }
            return (EidLoginTx) e[0];
        }

        @Override
        public synchronized void set(EidLoginTx tx, Duration ttl) {
            Instant now = clock.instant();
            if (!m.containsKey(tx.sessionId()) && m.size() >= max) {
                for (Iterator<Object[]> it = m.values().iterator(); it.hasNext(); ) {
                    if (!now.isBefore((Instant) it.next()[1])) it.remove();
                }
                if (m.size() >= max) throw new StoreFullException();
            }
            m.put(tx.sessionId(), new Object[] {tx, now.plus(ttl)});
        }

        @Override
        public synchronized boolean delete(String k) {
            return m.remove(k) != null;
        }

        synchronized int size() {
            return m.size();
        }
    }
}
