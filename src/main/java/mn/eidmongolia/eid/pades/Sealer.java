package mn.eidmongolia.eid.pades;

import mn.eidmongolia.eid.HashAlgorithm;
import mn.eidmongolia.eid.SealCertificate;
import mn.eidmongolia.eid.SealResult;

/**
 * The organisation seal RP-API {@link EidPades#sealPdf} needs (Go {@code pades.Sealer}); {@code EidClient.seal()}
 * ({@link mn.eidmongolia.eid.SealService}) implements it — replaceable in tests.
 */
public interface Sealer {
    /** GET /seal/certificate/{orgEtsi}. */
    SealCertificate certificate(String orgEtsi);

    /** POST /seal/{orgEtsi}: the signature over {@code digest} (ECDSA DER). */
    SealResult seal(String orgEtsi, byte[] digest, HashAlgorithm hash);
}
