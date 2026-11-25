[Монгол](README.md) · English · [中文](README.zh-CN.md)

# eid-mongolia-sdk-java

**eID Mongolia** client-side PAdES — the Java (JVM, server-side) SDK. The PDF document **never goes to the eID server**:
you prepare the document on your own backend (`prepare`), have only the 32-byte hash (DTBS) signed with the citizen's phone or USB token,
and then embed the signature into the PDF (`complete`). The output is PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL, DSS).

This is a **native Java port** of the Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, profile
`pades-client/1`) — CI checks on Linux and Windows (Java 17, 21) that it produces output **byte-identical** to Go's golden vectors (verify page, QR, xref, CMS, TSA/OCSP/CRL
requests, DSS).

Full documentation: <https://developer.eidmongolia.mn/#overview>.

- Java 17+, **no runtime dependencies** — `java.security` + a small DER writer (no BouncyCastle, Jackson or Kotlin).
- Thread-safe, no global state. The network is used only in `complete` (TSA, OCSP/CRL) and in `EidQr.verify`'s default OCSP.
- **There is no RP-API client here.** Starting a citizen session, obtaining a `RAW_DIGEST_SIGNATURE` signature, `POST /pdf/signatures`,
  `POST /authentication/qr` and so on are done by calling the RP-API directly over HTTPS/JSON —
  [RP-API documentation](https://developer.eidmongolia.mn/#overview). This library only prepares/embeds the PDF, assembles the registration body,
  and parses/verifies "My QR".
- There is **no** full validator — verification: by the file's SHA-256 against the CA's registry; full cryptographic validation is in the Go
  backend SDK.

Other SDKs: [Go](https://github.com/gerege-systems/eid-mongolia-sdk-go) ·
[.NET](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet) ·
[Android](https://github.com/gerege-systems/eid-mongolia-sdk-android) ·
[Swift](https://github.com/gerege-systems/eid-mongolia-sdk-swift) ·
[Node.js/TypeScript](https://github.com/gerege-systems/eid-mongolia-sdk).

## Installation (JitPack)

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven("https://jitpack.io")
    }
}

// build.gradle.kts
dependencies {
    implementation("com.github.gerege-systems:eid-mongolia-sdk-java:0.1.1")
}
```

Maven:

```xml
<repositories>
  <repository><id>jitpack.io</id><url>https://jitpack.io</url></repository>
</repositories>
<dependency>
  <groupId>com.github.gerege-systems</groupId>
  <artifactId>eid-mongolia-sdk-java</artifactId>
  <version>0.1.1</version>
</dependency>
```

Version: the latest tag ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-java/releases) — the jar is also attached to
every release).

## Flow

```java
import mn.eidmongolia.eid.pades.*;

// 1. Бэлдэх — сүлжээгүй. signerCert = иргэний SIGN гэрчилгээ (RP-API-ийн сессийн хариунаас, DER).
Prepared prepared = EidPades.prepare(pdf, PrepareOptions.builder(signCertDer)
        .reason("Гэрээ баталгаажуулав")
        .claimedRole(claimedRole)           // байгууллагын нэрийн өмнөөс бол (RP-API representation хариунаас), эс бөгөөс null
        .verifyPage(true)                   // шалгах (QR) хуудас — зөвхөн эхний eID гарын үсэгт
        // .verifyPagePosition("first")     // QR хуудас 1-р хуудас болно (анхдагч "last")
        .fileName("Гэрээ №1.pdf")           // verifyPage = true бол заавал
        .lang("mn")                         // mn (анхдагч) | en
        // Сонголттой харагдах гарын үсэг: pt, хуудасны харагдах зүүн доод булангаас; page 0 = eID verify хуудас биш
        // сүүлийн хуудас. Өндөр ≥ 45 pt; багтахгүй бол REQUEST_INVALID. null = үл харагдах.
        .appearance(new SignatureAppearance(36, 36, 220, 64))
        .build());
// prepared.placement() — харагдах гарын үсгийн эцсийн байрлал (доорх «Байршил»).

// 2. prepared.dtbs() (32 байт)-ийг RP-API-ийн signature session-д (RAW_DIGEST_SIGNATURE) өгч утсаар зуруулна, эсвэл
//    USB токеноор (PKCS#11) зурна. prepared.state()-ийг хүлээх хооронд хадгалж болно (формат нь Go reference-тэй ижил).

// 3. Суулгах — TSA, OCSP/CRL сүлжээ (blocking — worker thread дээр). Гарын үсэг: RSA PKCS#1 v1.5, ECDSA r‖s эсвэл DER.
Completed done = EidPades.complete(prepared.state(), signature);
Files.write(Path.of("signed.pdf"), done.pdf());

// 4. Бүртгэх — RP-API POST /pdf/signatures-ийн бие (PDF биш, зөвхөн мета), ЯГ ХЭВЭЭР нь илгээнэ:
String body = done.registration(sessionId, orgRegNo).toJson();   // medium-ийг sessionId-аас: байвал PHONE, үгүй бол TOKEN
// эсвэл тодорхой: done.registration(Medium.TOKEN, null, null)
```

`registration(medium, sessionId, onBehalfOf)` throws `REQUEST_INVALID` before anything goes to the CA when: `Medium.PHONE` without
a `sessionId`, `Medium.TOKEN` with a `sessionId`, no verify page at revIndex 1, no `fileName`, or, for a prepare with a `claimedRole`, an empty
`onBehalfOf` (NTRMN-…). If `medium` is null it is derived from `sessionId` (the CA's pair: phone ⇔ sessionID).

Send previous signatures only via `priorCmsSha256` — if you send **both** `priorCmsSha256` and `priorRevisionSha256`
in full, the CA returns 400. If the previous signature was assembled by the CA (mode A), the CA returns 409 `PRIOR_MISMATCH`:
resend with `reg.withPriorByRevision(k)` (it moves the first k to `priorRevisionSha256`).

`CompleteOptions.builder()`: `tsaUrl` (default `https://tsa.timeserver.mn/`), `roots` (test PKI), `transport`
(`EidPadesTransport` — proxy/sandbox; the default is `HttpURLConnection`, a 10 s total deadline per request, no redirects followed,
≤ 4 MiB). The national CRL (`esign.gov.mn`) is fetched from eID's https mirror (WIRE.md §3).

## Errors

All errors are `EidPadesException` (unchecked); branch on `code()` (stable, the same across all SDKs),
and use `getMessage()` for logs only. `retryable()` — a transient TSA/LTV error (call `complete` again with the same state + signature).

| Code | Meaning |
|---|---|
| `PDF_INVALID` | the PDF cannot be parsed; structure too deep (nesting > 256), an ObjStm cycle, `/Extends` > 64, `/Size` > 2^21 (PRECHECKS #2a/#2b) |
| `PDF_ENCRYPTED` | an encrypted PDF |
| `PDF_LOCKED` | DocMDP P=1 — modification is forbidden |
| `PDF_TOO_LARGE` | larger than 9.75 MiB (input) / 10 MiB (output) |
| `PDF_TOO_MANY_SIGNATURES` | more than 16 signatures |
| `PDF_PRIOR_SIGNATURE_INVALID` | a previous signature is corrupt |
| `PDF_FOREIGN_SIGNATURE` | a previous signature is not an eID B-LT |
| `SIGNER_INVALID` | signerCert / chain is wrong |
| `REQUEST_INVALID` | an option is wrong (docId, lang, fileName, appearance, claimedRole, medium…) |
| `SIGNATURE_INVALID` | the signature does not match the DTBS / signerCert |
| `TSA_UNAVAILABLE` | the TSA did not respond / the token is invalid |
| `LTV_UNAVAILABLE` | OCSP/CRL could not be fully obtained; if `LtvUnavailable.certificateRevoked()`, a chain certificate is revoked — do not retry |
| `SELF_VALIDATION_FAILED` | the output did not pass its own validation |
| `PLACEHOLDER_OVERFLOW` | did not fit in the CMS placeholder |
| `STATE_INVALID` | the `state` is corrupt (or its PDF's structure is too deep/complex) |
| `INTERNAL` | an internal SDK error |

### Placement of the visible signature

`SignatureAppearance`'s `x/y` is the **requested** position. Prepare reads the target page (text, table rules, images, form
XObjects, annotation `/Rect`s) without rendering it, and if the requested rectangle (+4 pt) overlaps content it moves it to the first free
position (the mirrored column at the same height → up in 12 pt steps in the requested column → up in the mirrored column).
`prepared.placement()` (`page`, `x`, `y`, `width`, `height` — pt; `status`): `REQUESTED` | `MOVED` | `OVERLAP` (no free
space, at the requested position) | `UNSCANNED` (the page could not be read within the limit, at the requested position). It is advisable to tell the user about `OVERLAP` / `UNSCANNED`
— the signature is valid in every case. Rules: the Go repo's `pades/PLACEMENT_SPEC.md`.

**Letting the citizen place it** (PLACEMENT_SPEC §6a/§6b): `EidPades.suggestPlacement(pdf, appearance)` runs prepare's placement
without a signature, a certificate or the network and returns the default position and the page sizes (`pageWidth`, `pageHeight`, `pageCount`,
`pages()`). If you pass the position the citizen dragged to with `appearance.withExact(true)`, the stamp is drawn exactly there (it never
moves; over content it is `OVERLAP`, going off the page is `REQUEST_INVALID`). Screen (top-left, `s` px/pt) ↔ appearance:
`left = x·s`, `top = (pageHeight − y − height)·s`.

## "My QR" — the citizen's "My information" (`EidQr`)

The citizen shows "My QR" in the eID app (`EIDMN-QR1:<token>`) → the RP scans it and calls the RP-API `POST /authentication/qr`
**directly** → the citizen approves with PIN2 → the RP receives the citizen's "My information" as a
**PS256 JWS** signed with the citizen's QUALIFIED SIGN key (`typ` = `eidmn-myqr+jwt`, `x5c` = [the citizen's certificate, the issuing CA]). This library verifies the JWS:

```java
EidQr.Parsed qr = EidQr.parse(scanned);              // QR_FORMAT_INVALID бол RP-API руу явуулахгүй
// … qr.qr()-ийг POST /authentication/qr-д илгээж, session-ийн үр дүнгээс JWS-ийг авна (RP-API, шууд HTTPS)
EidQr.Result r = EidQr.verify(jws, new EidQr.Expect(rpUuid, sessionId, nonce));
for (Map.Entry<String, String> f : r.data()) show(f.getKey(), f.getValue());   // payload-ийн дарааллаар
// r.source(), r.photo() (JPEG | null), r.signer().etsi(), r.signedAt(), r.sha256() (= CA аудитын qrsha), r.jws()
```

Verification (the same as Go / TS / .NET, using the CA's `myqr_vectors.json`): JWS ≤ 512 KiB, 3 segments → the header is exactly `alg` PS256 / `typ` /
`x5c` of 2 certificates → chain (x5c[1] is only an intermediate candidate, ±60 s) + leaf: not a CA, KeyUsage contentCommitment,
QcCompliance, the issuer's SKI ∈ the allowed set (default 04 `EidQr.CITIZEN_ISSUING_CA_SKI`), RSA ≥ 2048 → revocation (default the AIA's
OCSP, hard-fail) → RSASSA-PSS SHA-256 (salt 32) → `iss`, `sub`, `statement`, `aud` (case-insensitive), `sid`, `nonce`,
0 < exp − iat ≤ 300, ±60 s → `data` limits. `EidQr.Trust(anchors, intermediates, allowedIssuerSkis, revocation,
revocationSoftFail)` — for null, the embedded national root + 02–05, issuer 04, OCSP.

Codes (`EidQrException.code()`): `QR_FORMAT_INVALID`, `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`, `QR_CHAIN_INVALID`,
`QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`, `QR_AUDIENCE_MISMATCH`,
`QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`. The RP-API's HTTP errors
(`QR_TOKEN_INVALID`, `QR_PRESENTATION_GONE` …) arrive in your HTTP client.

## Development

- Profile rules: the Go repo's `pades/PROFILE.md`, `PAGE_SPEC.md`, `PRECHECKS.md`, `WIRE.md`, `APPEARANCE_SPEC.md`,
  `PLACEMENT_SPEC.md`.
- Golden: `src/test/resources/golden` = the Go repo's `pades/testdata/golden` (+ the `validate/` inputs), from the tag in `golden/SOURCE`
  (`scripts/sync-pades-golden.sh <tag>`; the CI `golden-sync` job checks it with `--check`). The test PKI's private
  keys have been removed — the citizen's signature is ready in the manifest. `myqr_vectors.json` — the CA's contract vectors (sha256 pinned).
- Tests (`./gradlew build`, CI only): for every golden case, prepare → the manifest's signature → complete (HTTP fixture
  replay, fixed nonce/time) → the output PDF's sha256 is compared with Go's; placement vectors (every box), validate v4
  (revocation evidence, structural checks), error codes, "My QR" vectors.
- Fonts (`src/main/resources/.../fonts`): a Noto Sans subset, SIL OFL 1.1 — byte-identical to the Go reference's `pades/assets/fonts`.

## Release

1. A `release/<version>` branch: merge `changelog.d/*` into the `## <version> — <date>` section of `CHANGELOG.md` and
   delete them → PR → merge.
2. On main, `git tag <version> && git push origin <version>` (the tag has no `v` — JitPack's version = the tag, the same as the Android SDK).
3. `.github/workflows/release.yml`: runs the full CI (Linux + Windows) and attaches the jar/sources/javadoc to the GitHub Release.
   JitPack builds from the tag itself (`jitpack.yml`).

## License

MIT — [LICENSE](LICENSE). Fonts: SIL Open Font License 1.1 (`src/main/resources/mn/eidmongolia/eid/pades/fonts/OFL.txt`).
