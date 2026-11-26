Монгол · [English](README.en.md) · [中文](README.zh-CN.md)

# eid-mongolia-sdk-java

**eID Mongolia** client-side PAdES — Java (JVM, server-side) SDK. PDF баримт eID сервер рүү **хэзээ ч явахгүй**:
баримтыг өөрийн backend дээр бэлдэж (`prepare`), зөвхөн 32 байт хэш (DTBS)-ийг иргэний утас эсвэл USB токеноор
зуруулаад, гарын үсгийг PDF-д суулгана (`complete`). Гаралт нь PAdES-BASELINE-LT (RFC 3161 timestamp, OCSP/CRL, DSS).

Энэ нь Go reference ([eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) `pades`, профайл
`pades-client/1`)-ийн **native Java порт** — Go-ийн golden vector-уудтай (verify хуудас, QR, xref, CMS, TSA/OCSP/CRL
хүсэлт, DSS) **байт-ижил** гаргадгийг CI Linux ба Windows дээр (Java 17, 21) шалгадаг.

Бүрэн баримт: <https://developer.eidmongolia.mn/#overview>.

- Java 17+, **runtime хамааралгүй** — `java.security` + жижиг DER writer (BouncyCastle, Jackson, Kotlin үгүй).
- Thread-safe, глобал төлөвгүй. PAdES сүлжээг зөвхөн `complete`-д (TSA, OCSP/CRL) ба `EidQr.verify`-ийн анхдагч OCSP-д ашиглана.
- **Бүрэн RP-API клиент** (`mn.eidmongolia.eid`, 0.2.0-оос): нэвтрэлт, гарын үсэг, session, OCSP цуцлалттай хариуны
  validator, PDF гарын үсгийн бүртгэл, байгууллага / иргэн / e-Seal / токен / share, «Миний QR» клиент ба «eID-ээр нэвтрэх»
  товчны backend — Go ба TypeScript SDK-тэй ижил хүрээ (доорх дэмжлэгийн хүснэгт).
- Хараахан үгүй: гарын үсэгтэй PDF шалгах (ValidatePDF) — файлын SHA-256-аар CA-ийн бүртгэлээс шалга, эсвэл Go / TS SDK.


Бусад SDK: [Go](https://github.com/gerege-systems/eid-mongolia-sdk-go) ·
[.NET](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet) ·
[Android](https://github.com/gerege-systems/eid-mongolia-sdk-android) ·
[Swift](https://github.com/gerege-systems/eid-mongolia-sdk-swift) ·
[Node.js/TypeScript](https://github.com/gerege-systems/eid-mongolia-sdk).

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
    implementation("com.github.gerege-systems:eid-mongolia-sdk-java:0.2.0")
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
  <version>0.2.0</version>
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

## RP-API клиент (`mn.eidmongolia.eid`)

Бүрэн relying-party SDK — Go ба TypeScript SDK-тэй ижил хүрээ, ижил wire зан төлөв (cross-SDK conformance корпус
`rp-conformance/1`: wire, validator, OCSP, ACSP, interactions; нэвтрэх товчны backend-д `eidlogin/1`). Бүх дуудлага
блоклоно (virtual thread-д тохиромжтой); `Thread.interrupt()` явж буй дуудлагыг цуцална (`EidException.Network#cancelled`).

### Клиент, trust ба mTLS

```java
TrustConfig trust = TrustConfig.builder()
    .trustAnchorsPem(Roots.NATIONAL_ROOT_CA_PEM)          // шигтгэсэн үндэсний root (01); 02–04 дотроо бий
    .revocation(OcspRevocationChecker.create())           // checkRevocation-ийн OCSP (өгөхгүй бол унтраалттай)
    .revocationMode(RevocationMode.HARD_FAIL)             // checker өгсөн үеийн validator-ийн анхдагч
    .build();
EidClient eid = EidClient.builder(new Credentials(rpUuid, "Интернэт банк", apiSecret))
    .trust(trust)
    .transport(JdkHttpTransport.create(sslContext))      // mTLS: клиент гэрчилгээ SSLContext-д; анхдагч create()
    .language("mn")                                      // Accept-Language
    .build();                                            // baseUrl анхдагч https://rp.eidmongolia.mn
SessionTtl ttl = eid.auth().sessionTtl();                // discovery: auth / sign session-ий амьдрах хугацаа
```

- `baseUrl`: зөвхөн https (http нь зөвхөн localhost / loopback), хуучин `ca.eidmongolia.mn` хост тодорхой алдаа; Bearer
  API secret; дуудлага бүрд нийт deadline (анхдагч 15 с, PDF бүртгэл 80 с); JSON хариу ≤ 4 MiB; redirect дагахгүй.
- Алдаа: `EidException` (unchecked) — `Authentication` (401), `Forbidden` (403), `Api` ба код тус бүрийн дэд анги
  (`NoSigningCertificate`, `SealServiceDisabled` …), `Network`, `ResponseTooLarge`, `SessionFailed`, `Validation`
  (`reason()` = корпусын тогтвортой түлхүүр, ж: `chain.untrusted`), `Ocsp`, `DeviceLink`; бүгдэд `code()`, `status()`,
  `retryAfter()`, `retryable()`. Мессежид иргэний дугаар орохгүй. Автомат давталт үгүй (Go / TS шиг).

### Нэвтрэлт: push ба QR

```java
List<Interaction> ix = List.of(Interaction.displayTextAndPin("Интернэт банкинд нэвтрэх"));

// Иргэний утас руу push (регистр, иргэний дугаар эсвэл ETSI PNOMN-…)
NotificationSession push = eid.auth().notificationByEtsi("УБ12345678", ix, null);
show(push.vc());                                          // иргэний тулгах баталгаажуулах код

// Таны хуудсан дээрх QR (anonymous device link): секунд тутам шинэ QR холбоос
DeviceLinkSession qr = eid.auth().deviceLinkAnonymous(ix, null);
Thread ticker = new Thread(() -> {
    try {
        DeviceLink.tickQr(qr.linkInput(DeviceLinkType.QR, "mon").build(), Duration.ofSeconds(1), link -> render(link));
    } catch (InterruptedException e) { /* зогссон */ }
});
ticker.start();

// Session: үр дүнг хүлээгээд шалгана (гинж + ACSP_V2 гарын үсэг + урсгалын төрөл)
SessionResult res = eid.session().waitForResult(qr.sessionId(), WaitOptions.builder().expiresAt(qr.expiresAt()).build());
ticker.interrupt();
VerifiedIdentity id = eid.validator().validateAuth(res, qr.acsp(),
    ValidateAuthOptions.builder().expectedFlowType(FlowType.QR).build());
eid.validator().checkRevocation(id.certificate());       // OCSP (TrustConfig.revocation)
String etsi = id.subject().serialNumber();                // PNOMN-…
```

`session().poll(sessionId, serverPoll)` нь нэг long-poll; `waitForResult` COMPLETE эсвэл хугацаа дуустал давтана
(`maxWait` → `expiresAt` → discovery `sessionTtl` → 600 с, + 15 с). Web2App / App2App: `AuthOptions`-д `callbackUrl` өгч,
callback-ийн `userChallengeVerifier`-ийг `ValidateAuthOptions`-д дамжуул (эдгээр урсгалд заавал).

### Validator ба цуцлалт

`client.validator()` = `ResponseValidator`: `validateAuth` (ACSP_V2: урсгалын relay хаалт, userChallengeVerifier,
callback дүрэм, алгоритм / hash downgrade хаалт, гарын үсэг), `validateSign` (RAW_DIGEST: prehashed RSASSA-PSS,
PKCS#1 v1.5, ECDSA P-256), `validateCertificateChoice` → `Signer`. Гинжийг детерминист, гараар бичсэн угсрагч (PKIX
биш) барина: шигтгэсэн root, олгогчийн SKI allowlist, цагийн зөрүү, pathLen, KeyUsage / EKU, name constraints ба үл
таних critical extension-д fail-closed, гинжийн гарын үсэг зөвхөн SHA-2, RSA ≥ 2048, subject-д SERIALNUMBER эсвэл CN
нэгээс олон бол татгалзана (`subject.duplicate_identity`).

Цуцлалт (`OcspRevocationChecker`: OCSP `unknown` = цуцлагдсан, thisUpdate 48 ц дотор, кэш ≤ 5 мин, хүсэлт 2 с / нийт
3 с, CertID олгогчтой холбогдсон):

| Хаана | Анхдагч | OCSP хариугүй үед |
|---|---|---|
| `validator().checkRevocation` | `TrustConfig.revocation(...)` өгөх хүртэл **унтраалттай** | `HARD_FAIL` (өгсөн үеийн анхдагч) → `EidException.Validation`; `SOFT_FAIL` → `UNCHECKED`-ээр зөвшөөрнө |
| Нэвтрэх товчны backend (`EidLogin`) | OCSP **асаалттай**, **soft-fail** | зөвшөөрч log бичнэ, `identity.revocation() == UNCHECKED` |
| «Миний QR» (`EidQr.verify`, `client.qr()`) | OCSP асаалттай, hard-fail | `QR_REVOCATION_UNKNOWN` |

Нэвтрэх backend анхдагчаар **soft-fail** (OCSP тасарвал бүх хүн түгжигдэхгүй). **Өндөр үнэ цэнтэй RP (банк, нотариат,
мөнгө эсвэл хуулийн үр дагавартай бүх зүйл) hard-fail хэрэглэх нь зүйтэй**: `EidLogin.builder(eid)
.revocationMode(RevocationMode.HARD_FAIL)`, validator-т `TrustConfig.revocation(...)`.

### Гарын үсэг

```java
// Эхлээд гэрчилгээг мэдэх (client-side PAdES / CMS): гэрчилгээ сонголт → гарын үсэг зурагч
NotificationSession cc = eid.sign().certificateChoiceByEtsi("УБ12345678", null);
SessionResult ccr = eid.session().waitForResult(cc.sessionId(), WaitOptions.builder().expiresAt(cc.expiresAt()).build());
Signer signer = eid.validator().validateCertificateChoice(ccr, cc.sessionId());

// Digest (ж: EidPades.prepare(...).dtbs()) — утсан дээр PIN2-оор зурна
String dtbsB64 = Base64.getEncoder().encodeToString(prepared.dtbs());
NotificationSession s = eid.sign().digestForSigner(signer.ref(), dtbsB64, ix, null);
SessionResult sr = eid.session().waitForResult(s.sessionId(), WaitOptions.builder().expiresAt(s.expiresAt()).build());
VerifiedSignature sig = eid.validator().validateSign(sr, dtbsB64, HashAlgorithm.SHA_256);
```

Мөн `digestByEtsi`, `digestByDocument`, `textByEtsi`, `deviceLinkByEtsi` / `deviceLinkByDocument` /
`deviceLinkForSigner` (QR / Web2App), `certificateChoiceDeviceLink`; `SignOptions` (certificateLevel, hash /
гарын үсгийн алгоритм, `onBehalfOf`, callbackUrl, fileName).

### PDF гарын үсгийн бүртгэл

```java
Completed done = EidPades.complete(prepared.state(), Base64.getDecoder().decode(sig.signatureValueB64()));
PdfSignatureRegistered reg = eid.pdf().registerSignature(done.registration(s.sessionId(), null));
// reg.docId(), reg.revIndex() (1…16), reg.verifyUrl(), reg.created() (false = idempotent давталт)
```

`POST /pdf/signatures`; 409 `PRIOR_MISMATCH` үед өмнөх гарын үсгийн хослолуудыг Go / TS шиг дахин оролдоно. Буруу
оролт (docID / cms алга, revIndex 1…16-аас гадуур, утсанд sessionID алга …) ямар ч хүсэлтээс өмнө
`IllegalArgumentException`.

### Байгууллага, иргэн, e-Seal, токен, share

- `organization()`: `getRepresentations(personEtsi)`, `sealGrants(personEtsi)`.
- `person()` (PKI_READ): `certificates`, `devices`, `activity(etsi, ActivityQuery)`, `summary`, `children`.
- `seal()`: `certificate`, `requestCertificate`, `certificateRequest`, `waitForCertificate`, `requestGrant`,
  `grantStatus`, `waitForGrant`, `seal(orgEtsi, digest, hash)` — буцсан ECDSA гарын үсгийг e-Seal гэрчилгээгээр
  шалгана; `isSealCertificate`.
- `token()`: `issueCertificate`, `previewCertificate`, `certificateResult`, `certificateInfo`, `authChallenge`,
  `authVerify` (r‖s гарын үсэг ба гэрчилгээг илгээхээс өмнө validator-ийн гинжээр шалгана), static
  `verifyTokenCertificates`, `tokenAuthDigest`, `tokenLimitOf`.
- `share(ShareRequest)` (гарын үсэгтэй файлыг multipart имэйлээр; CA хадгалахгүй) ба `shareInfo()`.
- Замын параметр (ETSI / session / request id) хоосон, `.` эсвэл `..` бол ямар ч хүсэлтээс өмнө татгалзана.

### «Миний QR» клиент

```java
EidQr.Parsed p = eid.qr().parse(scanned);                           // QR_FORMAT_INVALID → бүү илгээ
QrSession qs = eid.qr().start(new QrStartRequest(p.qr()));            // POST /authentication/qr
EidQr.Result r = eid.qr().result(qs, WaitOptions.builder().maxWait(Duration.ofMinutes(2)).build());  // утсан дээр PIN2
// r.data(), r.signer().etsi(), r.photo() … — EidQr.verify-ээр шалгагдсан (дээрх «Миний QR»)
```

`check(qs, serverPoll)` нь нэг long-poll алхам; `verify(jws, qs)` гарт байгаа JWS-ийг шалгана.
`EidClient.Builder.qrTrust` / `qrIssuer` trust ба олгогчийг солино.

### PDF-д тамга дарах (`EidPades.sealPdf`)

```java
Completed sealed = EidPades.sealPdf(eid.seal(), "NTRMN-1234567", pdf, SealOptions.builder().invisible(true).build());
```

**Энэ хувилбарт зөвхөн үл харагдах тамга**: харагдах тамганы дардас ба QR-тэй тамга PAdES хөдөлгүүрийн golden v12 / v13-д
хүрэхийг хүлээж байна; `invisible(false)` (анхдагч) сүлжээгүйгээр `REQUEST_INVALID`.

### «eID-ээр нэвтрэх» товчны backend (`mn.eidmongolia.eid.login`)

Хөтчийн `<eid-login-button>` (TS SDK) ашигладаг backend — Go `eidlogin` / TS `createEidLogin`-тэй ижил JSON, cookie, статус код (conformance `eidlogin/1`-ийн 24 сценари). `EidLogin.handle(EidLoginRequest)` нь framework-аас хамааралгүй; JDK серверт `EidLoginHttpHandler`, Servlet / Spring-д доорх жишээ. Push нь бүртгэлтэй эсэхийг задлахгүй (decoy, 1 с доод хугацаа), cookie нь HttpOnly + Secure + SameSite=Lax, төлөв серверт (`EidLoginStore`, анхдагч санах ой), OCSP цуцлалт анхдагчаар (soft-fail — дээрхийг үз).

```java
EidLogin login = EidLogin.builder(eid)                      // eid = EidClient (trust: үндэсний root-тэй TrustConfig)
    .callbackUrl("https://bank.mn/auth/eid/callback")      // Web2App; зам яг /auth/eid/callback
    .failureRedirect("/login")
    .onSuccess((id, req) -> {                              // id.etsi() = PNOMN-…; ШИНЭ session үүсгэ
        String sid = sessions.create(id.etsi());
        return new EidLoginSuccess("/home", null, Map.of("Set-Cookie", List.of("sid=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Lax")));
    })
    .build();

// JDK com.sun.net.httpserver
HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
server.createContext("/auth/eid/", new EidLoginHttpHandler(login, EidLoginHttpHandler.ClientIp.direct()));
server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());   // Java 21+ — ЗААВАЛ (доор)
// server.setExecutor(Executors.newFixedThreadPool(64));           // Java 17: хязгаартай pool
server.start();
// JVM (секунд): -Dsun.net.httpserver.maxReqTime=10 -Dsun.net.httpserver.maxRspTime=30 — эсвэл timeout-тэй reverse proxy

// Servlet (jakarta.servlet) — /auth/eid/* руу
protected void service(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
    Map<String, List<String>> h = new HashMap<>();
    for (String n : Collections.list(rq.getHeaderNames())) h.put(n, Collections.list(rq.getHeaders(n)));
    String url = rq.getRequestURI() + (rq.getQueryString() == null ? "" : "?" + rq.getQueryString());
    byte[] body = rq.getInputStream().readNBytes(4097);          // дээд тал нь 4 KiB + 1 — илүүг EidLogin татгалзана
    EidLoginResponse r = login.handle(new EidLoginRequest(rq.getMethod(), url, h, body, rq.getRemoteAddr()));
    rs.setStatus(r.status());
    r.headers().forEach((k, vs) -> vs.forEach(v -> rs.addHeader(k, v)));
    rs.getOutputStream().write(r.body().getBytes(StandardCharsets.UTF_8));
}

// Spring MVC — биеийг өөрөө, хязгаартай уншина (хязгааргүй @RequestBody byte[] БҮҮ хэрэглэ)
@RequestMapping("/auth/eid/{op}")
ResponseEntity<String> eid(HttpServletRequest rq) throws IOException {
    Map<String, List<String>> h = new HashMap<>();
    for (String n : Collections.list(rq.getHeaderNames())) h.put(n, Collections.list(rq.getHeaders(n)));
    String url = rq.getRequestURI() + (rq.getQueryString() == null ? "" : "?" + rq.getQueryString());
    byte[] body = rq.getInputStream().readNBytes(4097);
    EidLoginResponse r = login.handle(new EidLoginRequest(rq.getMethod(), url, h, body, rq.getRemoteAddr()));
    HttpHeaders out = new HttpHeaders();
    r.headers().forEach(out::addAll);
    return new ResponseEntity<>(r.body(), out, HttpStatus.valueOf(r.status()));
}
```

**Thread.** `handle` блоклоно: status дуудлага thread-ээ `poll` хүртэл барина (анхдагч 1 с; нэг нэвтрэлтэд нэг удаад
нэг — ижил нэвтрэлтийн зэрэг ирсэн status шууд `PENDING` буцаана), push эхлэл 1 с доод хугацаанаас багагүй. Virtual thread
(Java 21+) эсвэл зэрэг нэвтрэлтийн тоонд тохирсон хязгаартай pool хэрэглэ. JDK `HttpServer` `setExecutor`-гүй бол бүх
хүсэлтийг НЭГ dispatcher thread дээр ажиллуулна — нэг удаан эсвэл давтагдсан клиент бүх нэвтрэлтийг зогсооно (handler нэг
удаа анхааруулга бичнэ). JDK сервер анхдагчаар унших deadline-гүй: `sun.net.httpserver.maxReqTime` / `maxRspTime`
(секунд) тохируул, эсвэл урд нь request timeout-тэй reverse proxy тавь.

**`start:<ip>` хязгаарын клиент IP — доорхоос яг НЭГИЙГ сонго.**

*A — клиент шууд холбогдоно (proxy-гүй):* builder-т `.clientIp(...)` БҮҮ дууд. Adapter socket-ийн хаягийг дамжуулна:
`EidLoginHttpHandler.ClientIp.direct()`, Servlet / Spring `rq.getRemoteAddr()` (дээрх шиг).

*B — N итгэмжит reverse proxy-ийн ард (ганц nginx = 1):*

```java
EidLogin login = EidLogin.builder(eid)
    .clientIp(EidLogin.forwardedClientIp(1))               // X-Forwarded-For, баруунаас 1 дэх утга
    // … дээрхтэй адил
    .build();
// JDK: ClientIp.trustedProxies(1) adapter-т мөн адил (тэгвэл builder-ийн clientIp-ийг бүү өг)
```

> **Анхааруулга:** builder-ийн `.clientIp(...)` нь adapter-ийн дамжуулсан хаягийг ДАРНА. B-г proxy-гүй орчинд хуулбал
> клиент бүр `X-Forwarded-For`-оор өөрийн хязгаарын түлхүүрийг сонгоно. Гаргаж чадаагүй хаяг (тохируулснаас богино proxy
> гинж) нэг хуваалцсан `start:unknown` хувинд тоологдоно; IPv6 клиентийг /64-өөр нь түлхүүрлэнэ. IP-ийн эх сурвалж огт
> байхгүй бол IP-ийн хязгаар унтарч, нэг удаа анхааруулга бичигдэнэ.

Дугаар тутмын push хязгаар (дугаарт минутад 3) зөвхөн дугаараар түлхүүрлэгдэнэ: иргэний регистрийн дугаарыг мэдсэн хэн ч
цонхыг дуусгаж тэр иргэний **push** нэвтрэлтийг минут хүртэл хойшлуулж чадна — дугаараар push хийхийн мөн чанар; QR ба
Web2App-д нөлөөлөхгүй.

### Дэмжлэгийн хүснэгт (Go / TypeScript SDK-тэй харьцуулбал)

| Боломж | Java 0.2.0 |
|---|---|
| Клиент, mTLS, алдаа, live discovery-тэй өдөр бүр тулгадаг замын хүснэгт | ✓ |
| Auth push / device link, QR ticker, ACSP_V2, interactions | ✓ |
| Session poll / waitForResult | ✓ |
| Гарын үсэг (push, device link, linked, text), гэрчилгээ сонголт | ✓ |
| Validator (auth, sign, гэрчилгээ сонголт), root, OCSP шалгагч, subject | ✓ |
| PDF гарын үсгийн бүртгэл (`POST /pdf/signatures`) | ✓ |
| Байгууллага, иргэн (PKI_READ), e-Seal (гэрчилгээ, grant, digest-д тамга), токен, share | ✓ |
| «Миний QR» parse / verify / start / result / check | ✓ |
| Нэвтрэх товчны backend (JDK adapter; Servlet / Spring жишээ) | ✓ |
| PAdES prepare / complete / suggestPlacement / бүртгэлийн бие | ✓ |
| `sealPdf` | зөвхөн үл харагдах — харагдах / QR-тэй тамга golden v12 / v13-ыг хүлээж байна |
| ValidatePDF (гарын үсэгтэй PDF шалгах) | хараахан үгүй |
| Тамганы бүртгэл (`POST /v3/seal/{org}/registrations`) | хараахан үгүй (ямар ч SDK-д алга) |

### 0.1.x-ээс шилжих

- Координат, jar-ын `Automatic-Module-Name` (`mn.eidmongolia.eid.pades` — нийцлийн тулд хэвээр, jar одоо
  `mn.eidmongolia.eid`, `.login`, `.internal`-ийг ч агуулна) ба `mn.eidmongolia.eid.pades`-ийн нийтийн API
  өөрчлөгдөөгүй: 0.2.0 зөвхөн нэмнэ (`EidPades.sealPdf`, `Sealer`, `SealOptions`, `EidQrException.TOKEN_INVALID` /
  `PENDING` / `PRESENTATION_GONE` ба cause-тай constructor). 0.1.1-ээр бичсэн код өөрчлөлтгүй compile, link хийгдэнэ
  (нэмэлтийн ердийн нэг сануулга: шинэ `Sealer` / `SealOptions` нэр хоёр wildcard import-ын дор өөр сангийн ижил нэртэй
  төрөлтэй давхцаж болно).
- `mn.eidmongolia.eid.internal` нь зөвхөн SDK-ийн өөрийн багцуудад нийтийн — API биш; ямар ч хувилбарт өөрчлөгдөж болно.
- Зан төлөвийн өөрчлөлт (илүү хатуу, аюулгүй байдал): «Миний QR» OCSP `unknown`-ийг цуцлагдсан гэж үзнэ
  (`QR_CERT_REVOKED`, өмнө нь `QR_REVOCATION_UNKNOWN`), 48 ц хүртэлх OCSP хариуг хүлээн авна (өмнө нь 24 ц); гэрчилгээ
  хатуу DER байх ёстой ([CHANGELOG.md](CHANGELOG.md)-ийн 0.2.0 аюулгүйн тэмдэглэл); SHA-1 гинжийн гарын үсэг ба 2048-аас
  бага RSA түлхүүр татгалзана; OCSP CertID олгогчтой таарах ёстой; subject-д SERIALNUMBER / CN давхардвал татгалзана.
- RP-API-г өөрөө HTTPS/JSON-оор дуудаж байсан бол `EidClient` руу хэсэг хэсгээр шилжиж болно — wire формат ижил.

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

Full English translation: [README.en.md](README.en.md).
