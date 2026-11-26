package mn.eidmongolia.eid.pades;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.Date;
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
}
