package mn.eidmongolia.eid;

import java.io.IOException;
import java.io.InputStream;

final class TestRes {
    private TestRes() {
    }

    static byte[] resource(String name) {
        try (InputStream s = TestRes.class.getResourceAsStream("/" + name)) {
            if (s == null) throw new IllegalStateException(name + " missing");
            return s.readAllBytes();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.toString();
    }
}
