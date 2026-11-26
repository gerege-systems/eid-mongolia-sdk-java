package mn.eidmongolia.eid.pades;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;
import mn.eidmongolia.eid.internal.Text;
import org.junit.Test;

/** The vendored pades-validate corpus: SHA256SUMS matches every file, every manifest input is vendored, SOURCE pins a commit. */
public class ValidatePdfCorpusIntegrityTest {
    @Test
    public void sha256sums() throws Exception {
        String sums = new String(ValidatePdfGoldenTest.res("SHA256SUMS"), StandardCharsets.UTF_8);
        int n = 0;
        for (String line : sums.split("\n")) {
            if (line.isEmpty()) continue;
            String[] p = line.split("  ", 2);
            assertEquals(p[1], p[0], Text.hex(MessageDigest.getInstance("SHA-256").digest(ValidatePdfGoldenTest.res(p[1]))));
            n++;
        }
        assertTrue(n > 0);
        for (Object c : (List<?>) ValidatePdfGoldenTest.manifest().get("cases")) {
            String in = ((Json.Obj) c).getString("input");
            assertTrue(in, sums.contains("  " + in + "\n"));
        }
        assertTrue(new String(ValidatePdfGoldenTest.res("SOURCE"), StandardCharsets.US_ASCII).trim().matches("[0-9a-f]{40}"));
    }
}
