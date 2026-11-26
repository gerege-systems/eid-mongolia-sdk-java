package mn.eidmongolia.eid;

import java.util.List;

/**
 * Every RP-API route the SDK calls (method + {param} template) — defined ONLY here (Go {@code routes.go}, TS
 * {@code contract.ts}); the contract test ({@code ContractTest}, workflow contract.yml) checks this list against the
 * live {@code /.well-known/eid}.
 */
final class Routes {
    private Routes() {
    }

    /** A route: method + path template with {param} placeholders. */
    record Route(String method, String path) {
        /**
         * The template with each {param} replaced, in order, by the path-escaped argument (Go {@code url.PathEscape}).
         *
         * @throws IllegalArgumentException wrong argument count, or an argument that is null, empty, "." or ".."
         */
        String expand(String... args) {
            StringBuilder b = new StringBuilder();
            String rest = path;
            for (String a : args) {
                int i = rest.indexOf('{');
                int j = rest.indexOf('}');
                if (i < 0 || j < i) throw new IllegalArgumentException("eid: route " + path + ": параметр илүү");
                // "", "." and ".." would change the path (/session/ → /session, /x/.. → /) — never sent.
                if (a == null || a.isEmpty() || a.equals(".") || a.equals("..")) {
                    throw new IllegalArgumentException("eid: route " + path + ": параметр хоосон, \".\" эсвэл \"..\" байж болохгүй");
                }
                b.append(rest, 0, i).append(pathEscape(a));
                rest = rest.substring(j + 1);
            }
            if (rest.indexOf('{') >= 0) throw new IllegalArgumentException("eid: route " + path + ": параметр дутуу");
            return b.append(rest).toString();
        }
    }

    static final Route AUTH_NOTIFICATION_ETSI = new Route("POST", "/authentication/notification/etsi/{semanticsIdentifier}");
    static final Route AUTH_NOTIFICATION_DOCUMENT = new Route("POST", "/authentication/notification/document/{documentNumber}");
    static final Route AUTH_DEVICE_LINK_ANONYMOUS = new Route("POST", "/authentication/device-link/anonymous");
    static final Route AUTH_DEVICE_LINK_ETSI = new Route("POST", "/authentication/device-link/etsi/{semanticsIdentifier}");
    static final Route AUTH_QR = new Route("POST", "/authentication/qr");
    static final Route SIGN_NOTIFICATION_ETSI = new Route("POST", "/signature/notification/etsi/{semanticsIdentifier}");
    static final Route SIGN_NOTIFICATION_DOCUMENT = new Route("POST", "/signature/notification/document/{documentNumber}");
    static final Route SIGN_NOTIFICATION_LINKED = new Route("POST", "/signature/notification/linked/{documentNumber}");
    static final Route SIGN_DEVICE_LINK_ETSI = new Route("POST", "/signature/device-link/etsi/{semanticsIdentifier}");
    static final Route SIGN_DEVICE_LINK_DOCUMENT = new Route("POST", "/signature/device-link/document/{documentNumber}");
    static final Route CERT_CHOICE_DEVICE_LINK = new Route("POST", "/signature/certificate-choice/device-link/anonymous");
    static final Route CERT_CHOICE_ETSI = new Route("POST", "/signature/certificate-choice/notification/etsi/{semanticsIdentifier}");
    static final Route PDF_SIGNATURES = new Route("POST", "/pdf/signatures");
    static final Route ORG_REPRESENTATIONS = new Route("GET", "/organization/representations/etsi/{personEtsi}");
    static final Route SESSION = new Route("GET", "/session/{sessionId}");
    static final Route PERSON_CERTIFICATES = new Route("GET", "/certificates/etsi/{personEtsi}");
    static final Route PERSON_DEVICES = new Route("GET", "/devices/etsi/{personEtsi}");
    static final Route PERSON_ACTIVITY = new Route("GET", "/rp/activity/etsi/{personEtsi}");
    static final Route PERSON_SUMMARY = new Route("GET", "/person/summary/etsi/{personEtsi}");
    static final Route PERSON_CHILDREN = new Route("GET", "/person/children/etsi/{personEtsi}");
    static final Route TOKEN_CERTIFICATE = new Route("POST", "/token/certificate");
    static final Route TOKEN_CERTIFICATE_RESULT = new Route("GET", "/token/certificate/{sessionID}");
    static final Route TOKEN_AUTH_CHALLENGE = new Route("POST", "/token/auth/challenge");
    static final Route TOKEN_AUTH_VERIFY = new Route("POST", "/token/auth/verify");
    static final Route SHARE = new Route("POST", "/share");
    static final Route SEAL_CERTIFICATE = new Route("GET", "/seal/certificate/{orgEtsi}");
    static final Route SEAL_CERTIFICATE_REQUEST = new Route("POST", "/seal/certificate/{orgEtsi}");
    /** CA !483 (ORG_ONBOARDING §4.3); discovery: endpoints.seal.certificate_request. */
    static final Route SEAL_CERTIFICATE_REQUEST_STATUS = new Route("GET", "/seal/certificate/{orgEtsi}/requests/{requestId}");
    static final Route SEAL = new Route("POST", "/seal/{orgEtsi}");
    /** RP-initiated seal grant request (CA V156); discovery: endpoints.seal.grants, organization.seal_grants. */
    static final Route SEAL_GRANTS = new Route("POST", "/seal/grants");
    static final Route SEAL_GRANT_STATUS = new Route("GET", "/seal/grants/{grantId}");
    static final Route ORG_SEAL_GRANTS = new Route("GET", "/organization/seal-grants/etsi/{personEtsi}");

    /** Not an RP-API action route: the discovery document (sessionTtl, share, seal switches). */
    static final String DISCOVERY_PATH = "/.well-known/eid";

    /** Every RP-API route the SDK covers (Go {@code rpRoutes}, same order) — for the contract test. */
    static final List<Route> ALL = List.of(
        AUTH_NOTIFICATION_ETSI, AUTH_NOTIFICATION_DOCUMENT, AUTH_DEVICE_LINK_ANONYMOUS, AUTH_DEVICE_LINK_ETSI,
        AUTH_QR,
        SIGN_NOTIFICATION_ETSI, SIGN_NOTIFICATION_DOCUMENT, SIGN_NOTIFICATION_LINKED,
        SIGN_DEVICE_LINK_ETSI, SIGN_DEVICE_LINK_DOCUMENT,
        CERT_CHOICE_DEVICE_LINK, CERT_CHOICE_ETSI,
        PDF_SIGNATURES,
        ORG_REPRESENTATIONS,
        SESSION,
        PERSON_CERTIFICATES, PERSON_DEVICES, PERSON_ACTIVITY, PERSON_SUMMARY, PERSON_CHILDREN,
        TOKEN_CERTIFICATE, TOKEN_CERTIFICATE_RESULT,
        TOKEN_AUTH_CHALLENGE, TOKEN_AUTH_VERIFY,
        SHARE,
        SEAL_CERTIFICATE, SEAL_CERTIFICATE_REQUEST, SEAL_CERTIFICATE_REQUEST_STATUS, SEAL,
        SEAL_GRANTS, SEAL_GRANT_STATUS, ORG_SEAL_GRANTS);

    /**
     * Routes in the CA contract (code + docs) but not yet listed in the live discovery — the contract test only WARNs
     * about them; move them to {@link #ALL} once discovered (Go {@code rpRoutesUndiscovered}).
     */
    static final List<Route> UNDISCOVERED = List.of();

    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * Go {@code url.PathEscape}: UTF-8 bytes; unreserved (A–Z a–z 0–9 - . _ ~) and {@code $ & + : = @} stay, everything
     * else becomes %XX (upper-case hex).
     */
    static String pathEscape(String s) {
        StringBuilder b = new StringBuilder();
        for (byte x : EidCrypto.utf8(s)) {
            int c = x & 0xFF;
            boolean keep = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '-' || c == '.' || c == '_' || c == '~'
                || c == '$' || c == '&' || c == '+' || c == ':' || c == '=' || c == '@';
            if (keep) b.append((char) c);
            else b.append('%').append(HEX[c >> 4]).append(HEX[c & 0xF]);
        }
        return b.toString();
    }
}
