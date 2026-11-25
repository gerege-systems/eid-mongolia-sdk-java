package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.List;

/**
 * PAGE_SPEC.md §7 QR — ISO/IEC 18004, byte mode, ECC M, versions 1–6 (smallest that fits), FIXED mask 0 (no penalty
 * selection, so every language produces the same matrix). Port of the Go reference `pades/internal/qr`.
 */
final class QrCode {
    private QrCode() {
    }

    private static final int[][] VERSIONS = { // ecPerBlock, blocks, dataPerBlock
        {0, 0, 0}, {10, 1, 16}, {16, 1, 28}, {26, 1, 44}, {18, 2, 32}, {24, 2, 43}, {16, 4, 27},
    };
    private static final int[][] ALIGN = {{}, {}, {6, 18}, {6, 22}, {6, 26}, {6, 30}, {6, 34}};

    private static final int[] GF_EXP = new int[512];
    private static final int[] GF_LOG = new int[256];

    static {
        int x = 1;
        for (int k = 0; k < 255; k++) {
            GF_EXP[k] = x;
            GF_LOG[x] = k;
            x <<= 1;
            if ((x & 0x100) != 0) x ^= 0x11D;
        }
        for (int k = 255; k < 512; k++) GF_EXP[k] = GF_EXP[k - 255];
    }

    /** Matrix [row][col], true = dark; no quiet zone. */
    static boolean[][] encode(byte[] data) {
        int ver = 0;
        for (int v = 1; v <= 6; v++) {
            if (4 + 8 + 8 * data.length <= VERSIONS[v][1] * VERSIONS[v][2] * 8) {
                ver = v;
                break;
            }
        }
        if (ver == 0) throw new IllegalArgumentException("QR data too long (≤ 106 bytes)");
        int ec = VERSIONS[ver][0];
        int blocks = VERSIONS[ver][1];
        int dpb = VERSIONS[ver][2];
        int total = blocks * dpb;
        List<Boolean> bits = new ArrayList<>();
        put(bits, 0b0100, 4);
        put(bits, data.length, 8);
        for (byte b : data) put(bits, b & 0xff, 8);
        put(bits, 0, Math.min(4, total * 8 - bits.size()));
        while (bits.size() % 8 != 0) bits.add(false);
        List<Integer> cw = new ArrayList<>();
        for (int i = 0; i < bits.size(); i += 8) {
            int b = 0;
            for (int j = 0; j < 8; j++) if (bits.get(i + j)) b |= 1 << (7 - j);
            cw.add(b);
        }
        for (int i = 0; cw.size() < total; i++) cw.add(i % 2 == 0 ? 0xEC : 0x11);
        int[] gen = rsGenerator(ec);
        int[][] dataBlocks = new int[blocks][dpb];
        int[][] ecBlocks = new int[blocks][];
        for (int b = 0; b < blocks; b++) {
            for (int k = 0; k < dpb; k++) dataBlocks[b][k] = cw.get(b * dpb + k);
            ecBlocks[b] = rsRemainder(dataBlocks[b], gen);
        }
        int[] fin = new int[total + blocks * ec];
        int o = 0;
        for (int k = 0; k < dpb; k++) for (int b = 0; b < blocks; b++) fin[o++] = dataBlocks[b][k];
        for (int k = 0; k < ec; k++) for (int b = 0; b < blocks; b++) fin[o++] = ecBlocks[b][k];
        return place(ver, ALIGN[ver], fin);
    }

    private static void put(List<Boolean> bits, int v, int n) {
        for (int i = n - 1; i >= 0; i--) bits.add(((v >> i) & 1) == 1);
    }

    private static boolean[][] place(int ver, int[] align, int[] fin) {
        int n = 17 + 4 * ver;
        boolean[][] m = new boolean[n][n];
        boolean[][] fn = new boolean[n][n];
        finder(m, fn, n, 0, 0);
        finder(m, fn, n, 0, n - 7);
        finder(m, fn, n, n - 7, 0);
        for (int k = 8; k < n - 8; k++) {
            set(m, fn, 6, k, k % 2 == 0);
            set(m, fn, k, 6, k % 2 == 0);
        }
        for (int r : align) {
            for (int c : align) {
                if ((r < 9 && c < 9) || (r < 9 && c > n - 9) || (r > n - 9 && c < 9)) continue;
                for (int dr = -2; dr <= 2; dr++) {
                    for (int dc = -2; dc <= 2; dc++) set(m, fn, r + dr, c + dc, Math.max(Math.abs(dr), Math.abs(dc)) != 1);
                }
            }
        }
        int f = formatBits(0);
        for (int k = 0; k <= 5; k++) set(m, fn, k, 8, fb(f, k));
        set(m, fn, 7, 8, fb(f, 6));
        set(m, fn, 8, 8, fb(f, 7));
        set(m, fn, 8, 7, fb(f, 8));
        for (int k = 9; k < 15; k++) set(m, fn, 8, 14 - k, fb(f, k));
        for (int k = 0; k < 8; k++) set(m, fn, 8, n - 1 - k, fb(f, k));
        for (int k = 8; k < 15; k++) set(m, fn, n - 15 + k, 8, fb(f, k));
        set(m, fn, n - 8, 8, true);
        int bit = 0;
        boolean up = true;
        int col = n - 1;
        while (col > 0) {
            if (col == 6) col--;
            for (int k = 0; k < n; k++) {
                int r = up ? n - 1 - k : k;
                for (int c : new int[] {col, col - 1}) {
                    if (fn[r][c]) continue;
                    boolean dark = bit < fin.length * 8 && ((fin[bit / 8] >> (7 - bit % 8)) & 1) == 1;
                    bit++;
                    if ((r + c) % 2 == 0) dark = !dark;
                    m[r][c] = dark;
                }
            }
            up = !up;
            col -= 2;
        }
        return m;
    }

    private static boolean fb(int f, int k) {
        return ((f >> k) & 1) == 1;
    }

    private static void set(boolean[][] m, boolean[][] fn, int r, int c, boolean dark) {
        m[r][c] = dark;
        fn[r][c] = true;
    }

    private static void finder(boolean[][] m, boolean[][] fn, int n, int r0, int c0) {
        for (int r = -1; r <= 7; r++) {
            for (int c = -1; c <= 7; c++) {
                int rr = r0 + r;
                int cc = c0 + c;
                if (rr < 0 || cc < 0 || rr >= n || cc >= n) continue;
                boolean dark = r >= 0 && r <= 6 && c >= 0 && c <= 6
                    && (r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4));
                set(m, fn, rr, cc, dark);
            }
        }
    }

    private static int formatBits(int data) {
        int v = data << 10;
        for (int k = 14; k >= 10; k--) if (((v >> k) & 1) == 1) v ^= 0x537 << (k - 10);
        return ((data << 10) | v) ^ 0x5412;
    }

    private static int gfMul(int a, int b) {
        return a == 0 || b == 0 ? 0 : GF_EXP[GF_LOG[a] + GF_LOG[b]];
    }

    private static int[] rsGenerator(int n) {
        int[] g = {1};
        for (int k = 0; k < n; k++) {
            int[] next = new int[g.length + 1];
            for (int j = 0; j < g.length; j++) {
                next[j] ^= g[j];
                next[j + 1] ^= gfMul(g[j], GF_EXP[k]);
            }
            g = next;
        }
        int[] out = new int[g.length - 1];
        System.arraycopy(g, 1, out, 0, out.length);
        return out;
    }

    private static int[] rsRemainder(int[] data, int[] gen) {
        int[] rem = new int[gen.length];
        for (int d : data) {
            int f = d ^ rem[0];
            System.arraycopy(rem, 1, rem, 0, rem.length - 1);
            rem[rem.length - 1] = 0;
            for (int k = 0; k < gen.length; k++) rem[k] ^= gfMul(gen[k], f);
        }
        return rem;
    }
}
