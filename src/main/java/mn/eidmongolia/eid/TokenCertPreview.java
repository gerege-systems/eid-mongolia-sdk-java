package mn.eidmongolia.eid;

import java.util.List;

/** {@link TokenService#previewCertificate} (Go {@code TokenCertPreview}); supersedes empty when none. */
public record TokenCertPreview(List<TokenSupersede> supersedes) {
}
