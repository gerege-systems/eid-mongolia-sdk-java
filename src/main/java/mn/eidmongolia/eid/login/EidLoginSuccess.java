package mn.eidmongolia.eid.login;

import java.util.List;
import java.util.Map;

/**
 * {@link EidLogin.Builder#onSuccess}'s answer (Go {@code eidlogin.Success}, TS {@code EidLoginSuccess}).
 *
 * @param redirect where to go after sign-in; for the Web2App callback "" / null = the configured success redirect
 * @param data sent to the browser as "data" in the QR / push status answer (JSON: Map, List, String, Number, Boolean,
 *     null) — never secrets
 * @param headers extra response headers, e.g. your NEW session's Set-Cookie (session fixation: always a fresh session)
 */
public record EidLoginSuccess(String redirect, Object data, Map<String, List<String>> headers) {
    public EidLoginSuccess {
        headers = headers == null ? Map.of() : Map.copyOf(headers);
    }

    public static EidLoginSuccess redirect(String to) {
        return new EidLoginSuccess(to, null, null);
    }
}
