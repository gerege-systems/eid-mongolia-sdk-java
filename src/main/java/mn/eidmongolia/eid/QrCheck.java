package mn.eidmongolia.eid;

import mn.eidmongolia.eid.pades.EidQr;

/**
 * {@link QrService#check} result (Go {@code QRCheck}): complete false — the citizen has not answered yet (presentation
 * null).
 */
public record QrCheck(boolean complete, EidQr.Result presentation) {
}
