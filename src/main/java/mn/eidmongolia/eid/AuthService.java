package mn.eidmongolia.eid;

import java.time.Duration;

/**
 * Authentication ({@link EidClient#auth()}; Go {@code AuthService}). This release carries only the discovery
 * {@link #sessionTtl()}; push and device-link starts follow.
 */
public final class AuthService {
    private final RpHttp http;

    AuthService(RpHttp http) {
        this.http = http;
    }

    /**
     * Discovery {@code sessionTtl} ({@code {"auth": s, "sign": s}}) — the CA's live session lifetimes. Absent fields
     * (older CA) → {@link Duration#ZERO}. Blocking; an interrupt cancels it ({@link EidException.Network#cancelled()}).
     */
    public SessionTtl sessionTtl() {
        Json.Obj d = http.getJson(Routes.DISCOVERY_PATH, null).obj("GET " + Routes.DISCOVERY_PATH);
        Json.Obj t = d.optObj("sessionTtl");
        if (t == null) return new SessionTtl(Duration.ZERO, Duration.ZERO);
        long a = t.optLong("auth", 0);
        long s = t.optLong("sign", 0);
        return new SessionTtl(a > 0 ? Duration.ofSeconds(a) : Duration.ZERO, s > 0 ? Duration.ofSeconds(s) : Duration.ZERO);
    }
}
