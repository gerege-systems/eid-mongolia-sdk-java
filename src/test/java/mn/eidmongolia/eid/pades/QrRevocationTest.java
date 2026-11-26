package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import mn.eidmongolia.eid.EidHttpResponse;
import mn.eidmongolia.eid.EidTransport;
import mn.eidmongolia.eid.OcspRevocationChecker;
import mn.eidmongolia.eid.internal.Cert;
import org.junit.Test;

/**
 * «My QR» default revocation = the RP SDK's OCSP checker (Go {@code qrRevocation} + {@code NewOCSPChecker}): OCSP
 * «unknown» is revoked and thisUpdate may be 48 h old — not the PAdES LTV 24 h rule. Driven by the conformance corpus's
 * OCSP scenarios (src/test/resources/conformance/ocsp).
 */
public class QrRevocationTest {
    private static String status(String name) {
        Json.Obj f = (Json.Obj) Json.parse(Golden.resource("conformance/ocsp/cases.json"));
        Json.Obj c = null;
        for (Object o : f.getArr("cases")) {
            if (((Json.Obj) o).getString("name").equals(name)) c = (Json.Obj) o;
        }
        Json.Obj http = c.getObj("http");
        EidTransport replay = r -> {
            Json.Obj rep = http.optObj(r.method() + " " + r.uri());
            if (rep == null) return new EidHttpResponse(404, Map.of(), new byte[0]);
            return new EidHttpResponse((int) rep.getLong("status"), Map.of("Content-Type", List.of(rep.getString("contentType"))),
                Base64.getDecoder().decode(rep.getString("bodyB64")));
        };
        OcspRevocationChecker checker = OcspRevocationChecker.builder().transport(replay).bindCertId(true)
            .clock(Clock.fixed(Instant.parse(c.getString("now")), ZoneOffset.UTC)).build();
        Cert leaf = Cert.parse(Cert.pemSingle(Golden.resource("conformance/" + c.getString("certificate"))));
        Cert issuer = Cert.parse(Cert.pemSingle(Golden.resource("conformance/" + c.getString("issuer"))));
        return EidQr.revocationStatus(checker, leaf, issuer);
    }

    @Test
    public void defaultRevocationRule() {
        assertEquals("good", status("good"));
        assertEquals("revoked", status("revoked"));
        // Before 0.2.0: "unknown" → QR_REVOCATION_UNKNOWN; now QR_CERT_REVOKED like Go / TS.
        assertEquals("revoked", status("unknown-is-revoked"));
        // 47 h old, no nextUpdate: accepted by the 48 h window (the LTV 24 h rule would say "unknown").
        assertEquals("good", status("max-age-edge-47h"));
        assertEquals("unknown", status("stale-49h"));
        assertEquals("unknown", status("bad-signature"));
        assertEquals("unknown", status("no-reply"));
    }
}
