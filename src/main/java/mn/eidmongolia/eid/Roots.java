package mn.eidmongolia.eid;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * The embedded eID Mongolia trust material (Go {@code roots.go}, TS {@code NATIONAL_ROOT_CA_PEM} /
 * {@code CITIZEN_INTERMEDIATES_PEM}) — the same certificates as the PAdES chain (Go
 * {@code pades/internal/eidcrypto/chain}), byte for byte (RootsTest pins their SHA-256).
 */
public final class Roots {
    private Roots() {
    }

    /**
     * Mongolian National Root CA (chain 01, the trust anchor) — for {@link TrustConfig.Builder#trustAnchorsPem}. Public
     * source: https://ca.eidmongolia.mn/pki/mongolian-national-root-ca.cer; SHA-256
     * CB:E7:F3:FE:1F:04:80:37:C2:15:DA:32:1E:58:CA:A4:F3:63:DE:9E:54:BB:C4:42:A3:BF:D6:2F:AD:83:44:82, valid until
     * 2031-02-01.
     */
    public static final String NATIONAL_ROOT_CA_PEM = pem("01-mongolian-national-root-ca.pem");

    /**
     * The citizen certificates' intermediates (leaf ↔ {@link #NATIONAL_ROOT_CA_PEM}): 02 Mongolian National Issuing CA
     * (MDDC) → 03 Gerege Issuing CA → 04 eID Mongolia Issuing CA (SKI = {@link #CITIZEN_ISSUING_CA_SKI}). RP-API responses
     * carry no chain — the default of {@link TrustConfig.Builder#intermediatesPem}.
     */
    public static final List<String> CITIZEN_INTERMEDIATES_PEM = List.of(pem("02-mongolian-national-issuing-ca-mddc.pem"),
        pem("03-gerege-issuing-ca.pem"), pem("04-eid-mongolia-issuing-ca.pem"));

    /**
     * Subject Key Identifier of eID Mongolia Issuing CA (04) — the only CA that issues citizen phone and USB token
     * AUTH/SIGN certificates; the default issuer allowlist ({@link TrustConfig.Builder#allowedIssuerSkis}).
     */
    public static final String CITIZEN_ISSUING_CA_SKI = "b8a37f2c64ad677912db7d9e34f246358a2fb909";

    private static String pem(String name) {
        try (InputStream s = Roots.class.getResourceAsStream("/mn/eidmongolia/eid/pades/chain/" + name)) {
            if (s == null) throw new IllegalStateException("resource " + name + " missing");
            return new String(s.readAllBytes(), StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException("resource " + name, e);
        }
    }
}
