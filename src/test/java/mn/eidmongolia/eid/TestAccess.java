package mn.eidmongolia.eid;

import java.time.Clock;

/** Package-private test hooks of the core, for tests in other packages (login). TEST ONLY. */
public final class TestAccess {
    private TestAccess() {
    }

    /** {@link EidClient.Builder#clock} (package-private in the SDK). */
    public static EidClient.Builder clock(EidClient.Builder b, Clock c) {
        return b.clock(c);
    }
}
