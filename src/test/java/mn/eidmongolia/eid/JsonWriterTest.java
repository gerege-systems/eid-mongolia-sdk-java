package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

/** {@link Json#stringify}: JS JSON.stringify output for request bodies; round trip through the strict reader. */
public class JsonWriterTest {
    @Test
    public void objectsArraysScalars() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("relyingPartyUUID", "00000000-0000-0000-0000-000000000000");
        m.put("skipped", null); // like JS undefined
        m.put("n", 42L);
        m.put("i", 7);
        m.put("big", new BigInteger("123456789012345678901234567890"));
        m.put("ok", true);
        m.put("list", Arrays.asList("a", null, false));
        m.put("nested", Map.of("k", List.of()));
        m.put("nul", Json.NULL);
        String s = Json.stringify(m);
        assertEquals("{\"relyingPartyUUID\":\"00000000-0000-0000-0000-000000000000\",\"n\":42,\"i\":7,"
            + "\"big\":123456789012345678901234567890,\"ok\":true,\"list\":[\"a\",null,false],\"nested\":{\"k\":[]},\"nul\":null}", s);
        Json.Obj back = (Json.Obj) Json.parse(s);
        assertEquals(42L, back.optLong("n", 0));
        assertTrue(back.optBool("ok", false));
        assertEquals(List.of("relyingPartyUUID", "n", "i", "big", "ok", "list", "nested", "nul"), List.copyOf(back.keySet()));
    }

    @Test
    public void stringRoundTrip() {
        String tricky = "Банк <А&Б> \"q\" \\ / \b\f\n\r\t \u0000 \u001f \u2028\u2029 \uD83D\uDE00";
        String s = Json.stringify(tricky);
        assertEquals(tricky, Json.parse(s));
        assertEquals("\"\\u0000\"", Json.stringify("\u0000"));
    }

    @Test
    public void rejectsUnsupported() {
        try {
            Json.stringify(1.5);
            fail("double зөвшөөрөгдөв");
        } catch (IllegalArgumentException expected) {
            // ok — numbers are integers only (no JS/Java float formatting divergence)
        }
        try {
            Json.stringify(Map.of(1, "x"));
            fail("string биш түлхүүр");
        } catch (IllegalArgumentException expected) {
            // ok
        }
    }
}
