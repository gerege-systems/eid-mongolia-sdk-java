package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import mn.eidmongolia.eid.internal.Cert;
import mn.eidmongolia.eid.internal.Text;

/** Vendored golden vectors (classpath `/golden/…`). */
final class Golden {
    private Golden() {
    }

    static byte[] file(String name) {
        try (InputStream s = Golden.class.getResourceAsStream("/golden/" + name)) {
            if (s == null) throw new IllegalStateException("golden/" + name + " missing");
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] resource(String name) {
        try (InputStream s = Golden.class.getResourceAsStream("/" + name)) {
            if (s == null) throw new IllegalStateException(name + " missing");
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] pem(String name) {
        return Cert.pemSingle(file(name));
    }

    static Json.Obj manifest() {
        return (Json.Obj) Json.parse(file("manifest.json"));
    }

    static Date time(String s) {
        return Date.from(OffsetDateTime.parse(s).toInstant());
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Replay transport: key = "METHOD URL hex(SHA-256(body))[0:16]" (WIRE.md). */
    static EidPadesTransport replay(Json.Obj m) {
        return (method, url, ct, body) -> {
            String key = method + " " + url + " " + Text.hex(Cms.sha256(body == null ? new byte[0] : body)).substring(0, 16);
            String f = m.getObj("http").optString(key);
            if (f.isEmpty()) throw new IOException("no golden HTTP fixture for " + key);
            return file(f);
        };
    }

    /** WIRE.md §4: nonce = first 8 bytes of SHA-256("golden-nonce:<case>" ‖ 0x00). */
    static byte[] nonce(String name) {
        byte[] seed = ("golden-nonce:" + name).getBytes(StandardCharsets.UTF_8);
        byte[] in = new byte[seed.length + 1];
        System.arraycopy(seed, 0, in, 0, seed.length);
        byte[] h = Cms.sha256(in);
        byte[] out = new byte[8];
        System.arraycopy(h, 0, out, 0, 8);
        return out;
    }

    static Pades.Env env(Date now, String name) {
        return new Pades.Env(() -> now, ms -> { }, () -> nonce(name));
    }

    static List<byte[]> chain() {
        return Arrays.asList(pem("pki/04.pem"), pem("pki/03.pem"), pem("pki/02.pem"));
    }

    static Json.Obj caseNamed(Json.Obj m, String name) {
        for (Object o : m.getArr("cases")) {
            Json.Obj c = (Json.Obj) o;
            if (c.getString("name").equals(name)) return c;
        }
        throw new IllegalStateException("no golden case " + name);
    }

    static SignatureAppearance appearance(Json.Obj p) {
        Json.Obj ap = p.optObj("appearance");
        return ap == null ? null : new SignatureAppearance(ap.optInt("page", 0), ap.getDouble("x"), ap.getDouble("y"), ap.getDouble("width"),
            ap.getDouble("height"), ap.optNonEmpty("lang"), ap.optBool("exact", false));
    }

    /**
     * A case's PrepareOptions (Go golden_test runGoldenWith): "signer": "seal" = pki/seal.pem (golden v12, the organisation
     * e-Seal → seal stamp), else pki/citizen.pem; "sealQr" = the unexported QR seal stamp variant (golden v13).
     */
    static PrepareOptions prepareOptions(Json.Obj m, Json.Obj c) {
        String name = c.getString("name");
        String signer = c.optString("signer");
        if (!signer.isEmpty() && !signer.equals("seal")) throw new IllegalStateException(name + ": signer " + signer);
        Json.Obj p = c.getObj("prepare");
        return PrepareOptions.builder(pem(signer.isEmpty() ? "pki/citizen.pem" : "pki/seal.pem")).sealQr(c.optBool("sealQr", false))
            .chain(chain()).signingTime(time(m.getString("signingTime"))).signerName(p.optNonEmpty("signerName"))
            .reason(p.optNonEmpty("reason")).claimedRole(p.optNonEmpty("claimedRole")).docId(p.optNonEmpty("docId"))
            .verifyPage(p.optBool("verifyPage", false)).fileName(p.optNonEmpty("fileName")).lang(p.optNonEmpty("lang"))
            .verifyPagePosition(p.optNonEmpty("verifyPagePosition")).appearance(appearance(p)).build();
    }

    static CompleteOptions completeOptions(Json.Obj m) {
        return CompleteOptions.builder().tsaUrl("http://tsa.pki.test/").roots(Collections.singletonList(pem("pki/root.pem")))
            .transport(replay(m)).build();
    }

    private static final Map<String, byte[]> OUTPUTS = new ConcurrentHashMap<>();

    /** A completed case's output PDF (Go testdata/golden/output/<name>.pdf — not vendored, rebuilt from the vectors). */
    static byte[] output(String name) {
        byte[] hit = OUTPUTS.get(name);
        if (hit != null) return hit;
        Json.Obj m = manifest();
        Json.Obj c = caseNamed(m, name);
        String in = c.getString("input");
        byte[] input = in.startsWith("case:") ? output(in.substring(5)) : file(in);
        Prepared prep = Pades.prepare(input, prepareOptions(m, c));
        Completed res = Pades.complete(prep.stateRaw(), Text.unhex(c.getObj("expect").getString("signature")), completeOptions(m),
            env(time(m.getString("now")), name));
        if (!res.outSha256().equals(c.getObj("expect").getString("outSha256"))) throw new IllegalStateException(name + ": outSha256");
        OUTPUTS.put(name, res.pdfRaw());
        return res.pdfRaw();
    }
}
