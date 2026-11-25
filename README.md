# eid-mongolia-sdk-java

**eID Mongolia** client-side PAdES — Java (JVM, server-side) SDK. PDF баримт eID сервер рүү **хэзээ ч явахгүй**:
баримтыг өөрийн backend дээр бэлдэж (`prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB токеноор
зуруулаад, гарын үсгийг PDF-д суулгана (`complete`). Гаралт нь PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL, DSS).

Энэ нь Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, профайл
`pades-client/1`)-ийн **native Java порт** — Go-ийн golden vector-уудтай (verify хуудас, QR, xref, CMS, TSA/OCSP/CRL
хүсэлт, DSS) **байт-ижил** гаргадгийг CI Linux ба Windows дээр (Java 17, 21) шалгадаг.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

- Java 17+, **runtime хамааралгүй** — `java.security` + жижиг DER writer (BouncyCastle, Jackson, Kotlin үгүй).
- Thread-safe, глобал төлөвгүй. Сүлжээ зөвхөн `complete`-д (TSA, OCSP/CRL) ба `EidQr.verify`-ийн анхдагч OCSP-д.
- **RP-API клиент энд байхгүй.** Иргэний сесс эхлүүлэх, `RAW_DIGEST_SIGNATURE` гарын үсэг авах, `POST /pdf/signatures`,
  `POST /authentication/qr` зэргийг RP-API-г шууд HTTPS/JSON-оор дуудна —
  [RP-API баримт](https://developer.eidmongolia.mn/#overview). Энэ сан зөвхөн PDF бэлдэх/суулгах, бүртгэлийн биеийг
  угсрах, «Миний QR»-ийг задлах/шалгах ажлыг хийнэ.
- Бүрэн шалгагч (validator) **байхгүй** — шалгалт: файлын SHA-256-аар CA-ийн бүртгэлээс, бүрэн криптограф шалгалт Go
  backend SDK-д.

Бусад SDK: [Go](https://github.com/gerege-systems/eid-mongolia-sdk-go) ·
[.NET](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet) ·
[Android](https://github.com/gerege-systems/eid-mongolia-sdk-android) ·
[Swift](https://github.com/gerege-systems/eid-mongolia-sdk-swift) ·
[Node.js/TypeScript](https://github.com/gerege-systems/eid-mongolia-sdk).

[English summary](#english)

## Суулгах (JitPack)

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

Хувилбар: хамгийн сүүлийн tag ([releases](https://github.com/gerege-systems/eid-mongolia-sdk-java/releases) — jar нь
release бүрд мөн хавсарсан).

## Урсгал

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

`registration(medium, sessionId, onBehalfOf)` нь CA руу явахаас өмнө `REQUEST_INVALID` шиднэ: `Medium.PHONE` +
`sessionId`-гүй, `Medium.TOKEN` + `sessionId`, revIndex 1 verify хуудасгүй, `fileName`-гүй, эсвэл `claimedRole`-той
prepare-д `onBehalfOf` (NTRMN-…) хоосон. `medium` null бол `sessionId`-аас (CA-ийн хос: phone ⇔ sessionID).

Өмнөх гарын үсгүүдийг зөвхөн `priorCmsSha256`-аар илгээнэ — `priorCmsSha256` ба `priorRevisionSha256`-г **хоёуланг нь**
бүтнээр илгээвэл CA 400 буцаана. Өмнөх гарын үсэг CA-д угсарсан (горим A) байвал CA 409 `PRIOR_MISMATCH` буцаана:
`reg.withPriorByRevision(k)` (эхний k-г `priorRevisionSha256` руу шилжүүлнэ)-ээр дахин илгээнэ.

`CompleteOptions.builder()`: `tsaUrl` (анхдагч `https://tsa.timeserver.mn/`), `roots` (тест PKI), `transport`
(`EidPadesTransport` — proxy/sandbox; анхдагч нь `HttpURLConnection`, хүсэлт бүрд 10 с нийт deadline, redirect дагахгүй,
≤ 4 MiB). Үндэсний CRL (`esign.gov.mn`)-ийг eID-ийн https толин хуулбараас татна (WIRE.md §3).

## Алдаа

Бүх алдаа `EidPadesException` (unchecked); салаалахдаа `code()`-ийг (тогтвортой, бүх SDK-д ижил) ашиглана,
`getMessage()` зөвхөн лог. `retryable()` — TSA/LTV түр алдаа (ижил state + гарын үсгээр `complete`-ийг дахин дуудна).

| Код | Утга |
|---|---|
| `PDF_INVALID` | PDF задрахгүй; бүтэц хэт гүн (давхарлалт > 256), ObjStm мөчлөг, `/Extends` > 64, `/Size` > 2^21 (PRECHECKS #2a/#2b) |
| `PDF_ENCRYPTED` | Шифрлэгдсэн PDF |
| `PDF_LOCKED` | DocMDP P=1 — өөрчлөхийг хориглосон |
| `PDF_TOO_LARGE` | 9.75 MiB (оролт) / 10 MiB (гаралт)-аас их |
| `PDF_TOO_MANY_SIGNATURES` | 16-аас олон гарын үсэг |
| `PDF_PRIOR_SIGNATURE_INVALID` | Өмнөх гарын үсэг эвдэрсэн |
| `PDF_FOREIGN_SIGNATURE` | Өмнөх гарын үсэг eID-ийн B-LT биш |
| `SIGNER_INVALID` | signerCert / гинж буруу |
| `REQUEST_INVALID` | Сонголт буруу (docId, lang, fileName, appearance, claimedRole, medium…) |
| `SIGNATURE_INVALID` | Гарын үсэг DTBS / signerCert-тэй таарахгүй |
| `TSA_UNAVAILABLE` | TSA хариу өгсөнгүй / token хүчингүй |
| `LTV_UNAVAILABLE` | OCSP/CRL бүрэн авч чадсангүй; `LtvUnavailable.certificateRevoked()` бол гинжийн гэрчилгээ цуцлагдсан — дахин оролдохгүй |
| `SELF_VALIDATION_FAILED` | Гаралт өөрийн шалгалтыг давсангүй |
| `PLACEHOLDER_OVERFLOW` | CMS placeholder-т багтсангүй |
| `STATE_INVALID` | `state` эвдэрсэн (эсвэл түүний PDF-ийн бүтэц хэт гүн/төвөгтэй) |
| `INTERNAL` | SDK-ийн дотоод алдаа |

### Харагдах гарын үсгийн байршил

`SignatureAppearance`-ийн `x/y` нь **хүссэн** байрлал. Prepare нь зорилтот хуудсыг (бичвэр, хүснэгтийн зураас, зураг, form
XObject, annotation-ий `/Rect`) рендергүйгээр уншаад, хүссэн тэгш өнцөгт (+4 pt) агуулгатай давхцвал эхний чөлөөт
байрлал руу шилжүүлнэ (толин багана ижил өндөрт → хүссэн баганаар 12 pt-ээр дээш → толин баганаар дээш).
`prepared.placement()` (`page`, `x`, `y`, `width`, `height` — pt; `status`): `REQUESTED` | `MOVED` | `OVERLAP` (чөлөөт
газар алга, хүссэн байрлалд) | `UNSCANNED` (хуудсыг хязгаарт уншиж чадсангүй, хүссэн байрлалд). `OVERLAP` / `UNSCANNED`-ийг
хэрэглэгчид мэдэгдэх нь зүйтэй — гарын үсэг аль ч тохиолдолд хүчинтэй. Дүрэм: Go репогийн `pades/PLACEMENT_SPEC.md`.

**Иргэн өөрөө байрлуулах** (PLACEMENT_SPEC §6a/§6b): `EidPades.suggestPlacement(pdf, appearance)` нь prepare-ийн байршлыг
гарын үсэг, гэрчилгээ, сүлжээгүйгээр ажиллуулж анхдагч байрлал, хуудасны хэмжээг (`pageWidth`, `pageHeight`, `pageCount`,
`pages()`) буцаана. Иргэн чирсэн байрлалыг `appearance.withExact(true)`-ээр өгвөл тамга яг тэнд зурагдана (хэзээ ч
шилжихгүй; агуулга дээр бол `OVERLAP`, хуудаснаас гарвал `REQUEST_INVALID`). Дэлгэц (зүүн дээд, `s` px/pt) ↔ appearance:
`left = x·s`, `top = (pageHeight − y − height)·s`.

## «Миний QR» — иргэний «Миний мэдээлэл» (`EidQr`)

Иргэн eID апп дээрээ «Миний QR»-ийг харуулна (`EIDMN-QR1:<token>`) → RP скан хийгээд RP-API `POST /authentication/qr`-ийг
**шууд** дуудна → иргэн PIN2-оор зөвшөөрнө → RP иргэний «Миний мэдээлэл»-ийг иргэний QUALIFIED SIGN түлхүүрээр зурсан
**PS256 JWS** (`typ` = `eidmn-myqr+jwt`, `x5c` = [иргэний гэрчилгээ, олгогч CA]) хэлбэрээр авна. Энэ сан JWS-ийг шалгана:

```java
EidQr.Parsed qr = EidQr.parse(scanned);              // QR_FORMAT_INVALID бол RP-API руу явуулахгүй
// … qr.qr()-ийг POST /authentication/qr-д илгээж, session-ийн үр дүнгээс JWS-ийг авна (RP-API, шууд HTTPS)
EidQr.Result r = EidQr.verify(jws, new EidQr.Expect(rpUuid, sessionId, nonce));
for (Map.Entry<String, String> f : r.data()) show(f.getKey(), f.getValue());   // payload-ийн дарааллаар
// r.source(), r.photo() (JPEG | null), r.signer().etsi(), r.signedAt(), r.sha256() (= CA аудитын qrsha), r.jws()
```

Шалгалт (Go / TS / .NET-тэй ижил, CA-ийн `myqr_vectors.json`): JWS ≤ 512 KiB, 3 сегмент → header яг `alg` PS256 / `typ` /
`x5c` 2 гэрчилгээ → гинж (x5c[1] зөвхөн завсрын нэр дэвшигч, ±60 с) + навч: CA биш, KeyUsage contentCommitment,
QcCompliance, олгогчийн SKI ∈ зөвшөөрөгдсөн (анхдагч 04 `EidQr.CITIZEN_ISSUING_CA_SKI`), RSA ≥ 2048 → цуцлалт (анхдагч AIA-ийн
OCSP, hard-fail) → RSASSA-PSS SHA-256 (salt 32) → `iss`, `sub`, `statement`, `aud` (том/жижиг үсэг ялгахгүй), `sid`, `nonce`,
0 < exp − iat ≤ 300, ±60 с → `data` хязгаар. `EidQr.Trust(anchors, intermediates, allowedIssuerSkis, revocation,
revocationSoftFail)` — null бол шигтгэсэн үндэсний root + 02–05, олгогч 04, OCSP.

Кодууд (`EidQrException.code()`): `QR_FORMAT_INVALID`, `QR_JWS_MALFORMED`, `QR_HEADER_INVALID`, `QR_CHAIN_INVALID`,
`QR_CERT_REVOKED`, `QR_REVOCATION_UNKNOWN`, `QR_SIGNATURE_INVALID`, `QR_CLAIMS_INVALID`, `QR_AUDIENCE_MISMATCH`,
`QR_SESSION_MISMATCH`, `QR_NONCE_MISMATCH`, `QR_NOT_YET_VALID`, `QR_EXPIRED`, `QR_DATA_INVALID`. RP-API-ийн HTTP алдаа
(`QR_TOKEN_INVALID`, `QR_PRESENTATION_GONE` …) таны HTTP клиентэд ирнэ.

## Хөгжүүлэлт

- Профайлын дүрэм: Go репогийн `pades/PROFILE.md`, `PAGE_SPEC.md`, `PRECHECKS.md`, `WIRE.md`, `APPEARANCE_SPEC.md`,
  `PLACEMENT_SPEC.md`.
- Golden: `src/test/resources/golden` = Go репогийн `pades/testdata/golden` (+ `validate/` оролтууд), `golden/SOURCE`
  tag-аас (`scripts/sync-pades-golden.sh <tag>`; CI `golden-sync` job нь `--check`-ээр тулгана). Тестийн PKI-ийн хувийн
  түлхүүр хасагдсан — иргэний гарын үсэг manifest-д бэлэн. `myqr_vectors.json` — CA-ийн гэрээний vector (sha256 бэхэлсэн).
- Тест (`./gradlew build`, зөвхөн CI-д): golden тохиолдол бүр prepare → manifest-ийн гарын үсэг → complete (HTTP fixture
  replay, тогтмол nonce/цаг) → гаралтын PDF-ийн sha256-ийг Go-ийнхтэй тулгана; placement vectors (box бүр), validate v4
  (цуцлалтын нотолгоо, бүтцийн шалгалт), алдааны кодууд, «Миний QR» vectors.
- Фонт (`src/main/resources/.../fonts`): Noto Sans subset, SIL OFL 1.1 — Go reference-ийн `pades/assets/fonts`-тай ижил байт.

## Release

1. `release/<хувилбар>` салбар: `changelog.d/*`-ийг `CHANGELOG.md`-ийн `## <хувилбар> — <огноо>` хэсэгт нэгтгээд
   устгана → PR → merge.
2. main дээр `git tag <хувилбар> && git push origin <хувилбар>` (tag нь `v`-гүй — JitPack-ийн хувилбар = tag, Android SDK-тэй ижил).
3. `.github/workflows/release.yml`: CI-г бүтнээр (Linux + Windows) ажиллуулж, jar/sources/javadoc-ийг GitHub Release-д
   хавсаргана. JitPack нь tag-аас өөрөө build хийнэ (`jitpack.yml`).

## Лиценз

MIT — [LICENSE](LICENSE). Фонт: SIL Open Font License 1.1 (`src/main/resources/mn/eidmongolia/eid/pades/fonts/OFL.txt`).

---

## English

Client-side PAdES for eID Mongolia in plain Java 17 (JVM, server-side), with **zero runtime dependencies**
(`java.security` + a small DER writer; no BouncyCastle, Jackson or Kotlin). The PDF never leaves your backend: `prepare`
writes the signature revision (optionally a bilingual verification page with a QR code and a visible stamp that avoids
page content) and returns the 32-byte DTBS; the citizen signs it on their phone (RP-API signature session,
`RAW_DIGEST_SIGNATURE`) or USB token; `complete` verifies the signature, gets an RFC 3161 timestamp, embeds the CAdES
CMS, collects OCSP/CRL and appends a DSS revision (PAdES-BASELINE-LT). `Completed.registration(...)` builds the
`POST /pdf/signatures` body (`toJson()`; medium PHONE ⇔ sessionId, TOKEN without). `EidQr.parse` / `EidQr.verify` check the
«My QR» PS256 JWS presentation (contract `myqr-2026-10-26`).

**There is no RP-API client in this library** — call the RP-API directly over HTTPS/JSON
(<https://developer.eidmongolia.mn/#overview>). Install from JitPack: add `https://jitpack.io` and
`com.github.gerege-systems:eid-mongolia-sdk-java:<tag>` (tags have no `v` prefix); jars are also attached to every GitHub
Release. This is a native port of the Go reference (`eid-mongolia-sdk-go/pades`, profile `pades-client/1`); CI proves
byte-identical output against the Go golden vectors on Linux and Windows (Java 17 and 21). No validator is shipped —
verification is a hash lookup against the CA registry; full cryptographic validation lives in the Go backend SDK.
Thread-safe, no global mutable state. Errors are unchecked `EidPadesException` / `EidQrException` with a stable `code()`.
Sibling SDKs: Go, .NET, Android, Swift, Node.js/TypeScript (links above).
