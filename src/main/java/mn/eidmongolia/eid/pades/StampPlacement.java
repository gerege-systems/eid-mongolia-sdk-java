package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.List;

/**
 * Visible stamp placement — PLACEMENT_SPEC.md (pades-client/1), 1:1 port of the Go reference
 * `pades/internal/core/placement.go` (`PlaceCandidates`, `PlaceVisible`). The requested rect is the preferred spot; the
 * page is scanned ([Occupancy]) into conservative h100 boxes and the stamp moves to the first free candidate.
 */
final class StampPlacement {
    enum Status {
        REQUESTED("requested"), MOVED("moved"), OVERLAP("overlap"), UNSCANNED("unscanned");

        final String wire;

        Status(String wire) {
            this.wire = wire;
        }
    }

    /** The stamp's lower-left corner in visible page space (h100) and how it was chosen. */
    static final class Result {
        final long x;
        final long y;
        final Status status;

        Result(long x, long y, Status status) {
            this.x = x;
            this.y = y;
            this.status = status;
        }
    }

    static final long PAD = 400L;      // h100: clearance kept around the stamp
    static final long STEP = 1200L;    // h100: vertical step between candidates
    static final int MAX_STEPS = 100;  // at most this many steps up per column

    private StampPlacement() {
    }

    /**
     * Candidate positions (visible space, h100) in trial order (§6): requested (x, y); mirrored (vw − x − w, y); then up the
     * requested column, then up the mirrored column. The mirrored column is left out when it equals the requested one.
     */
    static List<long[]> candidates(long vw, long vh, long x, long y, long w, long h) {
        long xl = vw - x - w;
        List<long[]> out = new ArrayList<>();
        out.add(new long[] {x, y});
        if (xl != x) out.add(new long[] {xl, y});
        long[] cols = xl != x ? new long[] {x, xl} : new long[] {x};
        for (long cx : cols) {
            for (int k = 1; k <= MAX_STEPS && y + k * STEP + h <= vh - y; k++) out.add(new long[] {cx, y + k * STEP});
        }
        return out;
    }

    /** The first candidate whose /Rect, grown by [PAD], overlaps no occupied box. null → none is free. */
    static long[] place(long[] box, int rot, long x, long y, long w, long h, List<long[]> occ) {
        long vw = box[2] - box[0];
        long vh = box[3] - box[1];
        if (rot == 90 || rot == 270) {
            long t = vw;
            vw = vh;
            vh = t;
        }
        for (long[] c : candidates(vw, vh, x, y, w, h)) {
            long[] r;
            try {
                r = Appearance.rect(box, rot, c[0], c[1], w, h);
            } catch (AppearanceException e) {
                continue;
            }
            if (free(r, occ)) return c;
        }
        return null;
    }

    /** [r] (user space, h100) grown by [PAD] overlaps no occupied box (strict overlap: touching edges are free). */
    static boolean free(long[] r, List<long[]> occ) {
        long[] e = {r[0] - PAD, r[1] - PAD, r[2] + PAD, r[3] + PAD};
        for (long[] b : occ) if (b[0] < e[2] && e[0] < b[2] && b[1] < e[3] && e[1] < b[3]) return false;
        return true;
    }

    /** Scan + choice for a visible stamp at (x, y, w, h) on [page] (reached as object [pageId]) — Go `PlaceOnPage`. */
    static Result choose(PdfReader rd, PdfDict page, int pageId, long[] box, int rot, long x, long y, long w, long h, boolean exact) {
        List<long[]> occ;
        try {
            occ = Occupancy.scan(rd, page, pageId, box);
        } catch (Exception e) {
            return new Result(x, y, Status.UNSCANNED);
        }
        if (exact) {
            long[] r;
            try {
                r = Appearance.rect(box, rot, x, y, w, h);
            } catch (AppearanceException e) {
                return new Result(x, y, Status.OVERLAP);
            }
            return new Result(x, y, free(r, occ) ? Status.REQUESTED : Status.OVERLAP);
        }
        long[] p = place(box, rot, x, y, w, h, occ);
        if (p == null) return new Result(x, y, Status.OVERLAP);
        return p[0] == x && p[1] == y ? new Result(x, y, Status.REQUESTED) : new Result(p[0], p[1], Status.MOVED);
    }

    /** [locate]'s result: the page (dict + reference), its /Rotate, the final /Rect (user space, h100) and the choice. */
    static final class Located {
        final PdfDict page;
        final PdfRef pageRef;
        final int rot;
        final long[] rect;
        final Result result;

        Located(PdfDict page, PdfRef pageRef, int rot, long[] rect, Result result) {
            this.page = page;
            this.pageRef = pageRef;
            this.rot = rot;
            this.rect = rect;
            this.result = result;
        }
    }

    /**
     * Where the stamp goes on page [page] (1-based, resolved) of the /Pages tree [pages] — the one path shared by
     * [SignatureRevision.prepare] and suggestPlacement: page → geometry → the requested rect must lie inside the page →
     * scan + choice.
     */
    static Located locate(PdfReader rd, PdfObj pages, PdfRef owner, int page, long x, long y, long w, long h, boolean exact) {
        Object[] p = Appearance.nthPage(rd, pages, owner, page);
        if (p == null) throw new AppearanceException("page " + page + " missing");
        PdfDict pd = (PdfDict) p[0];
        PdfRef pr = (PdfRef) p[1];
        Appearance.Geometry g = Appearance.geometry(rd, pd);
        long[] rect = Appearance.rect(g.box, g.rot, x, y, w, h);
        Result placed = choose(rd, pd, pr.id(), g.box, g.rot, x, y, w, h, exact);
        if (placed.status == Status.MOVED) rect = Appearance.rect(g.box, g.rot, placed.x, placed.y, w, h);
        return new Located(pd, pr, g.rot, rect, placed);
    }
}
