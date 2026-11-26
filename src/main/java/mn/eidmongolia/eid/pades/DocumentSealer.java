package mn.eidmongolia.eid.pades;

import mn.eidmongolia.eid.SealResult;

/**
 * A {@link Sealer} that reserves the document position when sealing (Go {@code pades.DocumentSealer}, CA V158);
 * {@code EidClient.seal()} ({@link mn.eidmongolia.eid.SealService}) implements it. Required by
 * {@link SealOptions#qr()}: the QR stamp promises {@code /verify/<docId>/<revIndex>}, so that position is reserved while
 * sealing. Plain {@link Sealer} implementations keep working for every other {@link EidPades#sealPdf} call.
 */
public interface DocumentSealer extends Sealer {
    /** POST /seal/{orgEtsi} {digest (SHA-256), docId, revIndex}: the signature over {@code digest} (ECDSA DER). */
    SealResult sealForDocument(String orgEtsi, byte[] digest, String docId, int revIndex);
}
