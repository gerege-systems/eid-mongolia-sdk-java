package mn.eidmongolia.eid.pades;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal PDF object model (ISO 32000-1 §7.3) for the incremental signature writer — reads only what a signature
 * revision needs; content streams are interpreted only by the placement scanner.
 */
interface PdfObj {
    PdfObj NULL = new Null();

    record Null() implements PdfObj {
    }

    record Bool(boolean v) implements PdfObj {
    }

    record Int(long v) implements PdfObj {
    }

    record Real(double v) implements PdfObj {
    }

    /** Raw string bytes (literal escapes resolved / hex decoded). */
    record Str(byte[] bytes) implements PdfObj {
    }

    record Name(String v) implements PdfObj {
    }

    record Arr(List<PdfObj> items) implements PdfObj {
    }

    record Dict(PdfDict d) implements PdfObj {
    }

    record Ref(PdfRef r) implements PdfObj {
    }

    /** Stream dictionary + raw (still encoded) data range [start, end) in the reader's bytes. */
    record Stream(PdfDict d, int start, int end) implements PdfObj {
    }

    default PdfDict dict() {
        if (this instanceof Dict) return ((Dict) this).d();
        if (this instanceof Stream) return ((Stream) this).d();
        return null;
    }

    default List<PdfObj> array() {
        return this instanceof Arr ? ((Arr) this).items() : null;
    }

    default String name() {
        return this instanceof Name ? ((Name) this).v() : null;
    }

    default boolean isNull() {
        return this instanceof Null;
    }

    default PdfRef ref() {
        return this instanceof Ref ? ((Ref) this).r() : null;
    }

    /** Integer value (an integral real counts), else null. */
    default Long asLong() {
        if (this instanceof Int) return ((Int) this).v();
        if (this instanceof Real) {
            double v = ((Real) this).v();
            if (v == Math.rint(v) && Math.abs(v) < 1e15) return (long) v;
        }
        return null;
    }
}

final class PdfException extends RuntimeException {
    PdfException(String msg) {
        super(msg);
    }
}

record PdfRef(int id, int gen) {
}

/** Names are kept one byte per char (Latin-1, `#xx` decoded); keys serialise sorted by byte (Go `sort.Strings`). */
final class PdfDict {
    final LinkedHashMap<String, PdfObj> entries = new LinkedHashMap<>();

    PdfObj get(String key) {
        PdfObj v = entries.get(key);
        return v == null ? PdfObj.NULL : v;
    }

    List<String> sortedKeys() {
        List<String> k = new ArrayList<>(entries.keySet());
        Collections.sort(k);
        return k;
    }

    Map<String, PdfObj> map() {
        return entries;
    }
}
