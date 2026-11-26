# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

## 0.3.0 — 2026-11-27

Same artifact and coordinates (`com.github.gerege-systems:eid-mongolia-sdk-java`, `Automatic-Module-Name`
`mn.eidmongolia.eid.pades`). New: `EidPades.validatePdf` — local validation of a signed PDF with the same report as
Go / TS and the CA `/v3/validate/pdf` (corpus v15, 80/80); seal registration (`seal().registerSealedPdf`,
`sealForDocument`, `SealOptions.qr / docId / fileName`); PAdES golden v13 — the organisation seal stamp, visible by
default in `sealPdf`; rp-conformance corpus v2 hardening (login cookie `__Host-eid_login`, hashed push rate-limit keys,
validator / OCSP weak-key rules, `RateRule.maxKeys`). The public API only gained members (source and binary compatible
with 0.2.0; see the `RateRule` note below). Read **Upgrade notes** before upgrading — several defaults changed.

### Security

- **Login cookie** (`mn.eidmongolia.eid.login`): the default name is now `__Host-eid_login` (Secure, no Domain, Path
  `/`), so a sibling host or another path can no longer set or shadow it; a request carrying the login cookie more than
  once is treated as having none (status `EXPIRED`, callback `eid_error=expired`).
- **No ID numbers in rate-limit keys:** the per-ID push limit is keyed `push:<hmac>` (the audit HMAC of the number, 32
  hex) instead of `push:<id>`, so custom `rateLimit` hooks, `RateRule.func` and external limiters (e.g. Redis) never
  store citizen ID numbers. `RateRule.maxKeys` bounds the in-memory limiter table.
- **Weak keys:** the validator reports `cert.weak_key` (RSA < 2048 bits, even or < 3 exponent) right after
  `cert.malformed`; the OCSP checker refuses a weak-key issuer (`no_issuer`, before cache / network) and a weak
  delegated responder (`signature`); a weak RSA key in the trust pool is a configuration error.
- **Hostile PDFs:** structural limits (Go `CheckStructure` / TS `checkStructure`) on xref sections, xref stream
  `/W` / `/Index`, entry counts, decompression and object-stream lookup work, applied by `prepare`, `complete`,
  `suggestPlacement`, `sealPdf` and `validatePdf`; the validator bounds CMS / timestamp certificates (≤ 32, serial
  ≤ 160 bits, RSA ≤ 8192 bits, e ≤ 2^32−1) and treats MD2 / MD5 / OIW SHA-1 SignerInfo algorithms as weak.
- **Later-signature rule:** only a later signature that passes integrity counts as an extension of an earlier one — a
  revision whose signature does not verify makes the earlier signatures `modified_after_signing`.

### Upgrade notes (from 0.2.0)

- `sealPdf` without options now draws a **visible** seal stamp (bottom-right, ≤ 220 × 64 pt; invisible when it does not
  fit). In 0.2.0 anything but `invisible(true)` was `REQUEST_INVALID`. `SealOptions.invisible(true)` keeps output
  byte-identical to 0.2.0 — use it while validators released before the seal stamp (older CA / TS SDK) are still in use,
  as they report earlier signatures as modified.
- `prepare` with an e-Seal certificate (KeyUsage nonRepudiation only, no EKU) and an appearance now draws the seal
  stamp instead of the personal signature stamp.
- On signed documents the docId is also read from an organisation seal stamp with QR (`/EIDVerify` marker), after the
  verify page; a `PrepareOptions.docId` that differs from the found one is `REQUEST_INVALID` (also for invisible
  signatures).
- The login cookie name change (`eid_login` → `__Host-eid_login` under the default Secure / no Domain / Path `/`
  settings; unchanged with `insecureCookie`, `cookieDomain`, another `cookiePath` or an explicit `cookieName`) restarts
  logins that are in progress during the upgrade once.
- Custom rate-limit hooks receive `push:<hmac>` instead of `push:<id>`. Instances that share one limiter must be
  configured with the same `auditKey`, otherwise each instance derives different keys.
- `EidLogin.RateRule` gained a fourth record component (`maxKeys`). The 0.2.0 three-argument constructor and accessors
  remain, so the change is source and binary compatible — but Java 21 record deconstruction patterns over `RateRule`
  (`case RateRule(var max, var window, var func)`) no longer compile and need the fourth component.
- Documents with more than 128 xref sections (incremental updates) or very large object streams are refused at
  `prepare` / `sealPdf` (`PDF_INVALID`) and reported `PDF_INVALID` by the validator (was `PDF_NO_SIGNATURE` or slow
  parsing); xref stream `/W` / `/Index` out of range likewise.
- A certificate with a weak (< 2048-bit) RSA key in the trust pool (anchors / intermediates) is now a configuration
  error: building the `ResponseValidator` throws `IllegalArgumentException` (was `chain.untrusted` at validation).

### Release preparation

- Version 0.3.0 (`build.gradle.kts` default; the tag still sets it for JitPack and the release workflow); README
  (mn / en / zh) install snippets (Gradle, Maven) and the support-matrix heading. The release workflow and
  `jitpack.yml` need no change. The SDK sends no versioned User-Agent, so there is no version constant in code.

### PAdES golden v11 → v13: байгууллагын тамганы дардас, QR-тэй тамга, docId дүрэм; `sealPdf` харагдах

- Юу:
  - Go reference (`eid-mongolia-sdk-go` `499aa5c`, golden v12 + v13 + §6.6 засварууд) байт-ижил порт: e-Seal гэрчилгээтэй
    харагдах гарын үсэг нь QR-гүй тамганы дардас (APPEARANCE_SPEC §6.2: тамганы label, үүргийн мөргүй, бүтэн өргөнтэй
    бичвэр); QR-тэй тамганы дардас (§6.5) — Go-той адил нийтийн бус (`PrepareOptions` дотоод `sealQr`, зөвхөн golden).
  - `prepare`-ийн docId дүрэм (§6.6, PRECHECKS): гарын үсэгтэй баримтад verify хуудас → шалгасан e-Seal гарын үсгийн хамгийн
    эрт зурсан `/EIDVerify` тэмдэгтэй дардас (шууд бус `/V`, ганц widget, маркерын rev = байрлал, `/Filter` алга/шууд null)
    → `PrepareOptions.docId`; олдсонтой зөрвөл `REQUEST_INVALID` (үл харагдах гарын үсэгт ч); санамсаргүй docId үүсгэхгүй.
  - `EidPades.sealPdf` (Go `SealPDF`): анхдагч нь харагдах тамганы дардас (автомат ≤ 220 × 64 pt баруун доод буланд,
    багтахгүй / `PDF_TOO_LARGE` бол үл харагдах), шинэ `SealOptions.appearance`, `Completed.placement()`,
    `EidPades.SEAL_STAMP_WIDTH/HEIGHT/MARGIN`. `invisible(true)` гаралт 0.2.0-тэй байт-ижил.
  - `wrapLimit` maxLines-аас цааш мөр үүсгэхгүй (Go `vpage.go`; гаралт ижил, урт бичвэрт квадрат хугацаагүй).
  - `scripts/sync-pades-golden.sh` нь commit SHA-аар pin хийнэ (Go репод v12/v13 tag алга); `golden/SOURCE` = `499aa5c…`.
- Зан төлөвийн өөрчлөлт: `sealPdf`-ийн анхдагч `REQUEST_INVALID` → харагдах дардас; гарын үсэгтэй баримтын docId нь
  тамганы QR-тэй дардсаас ч уншигдана. Нийтийн API зөвхөн нэмэгдсэн (0.2.0-тэй source/binary нийцтэй).
- Яагаад: Java PAdES хөдөлгүүрийг Go / .NET-тэй ижил golden-д хүргэж, «зөвхөн үл харагдах» хязгаарыг авах.
- Шалгасан: `./gradlew build` macmini (JDK 17) дээр — 198 тест ногоон (golden 54 тохиолдол — 50 complete хүртэл, шинэ `SealStampTest` 12:
  Go-ийн TestSealQRContent, TestResolveDocID, TestDocIDFromStamps*, TestPrepareDocIDRule, TestSealPDF* портууд, `sealPdf`
  анхдагчийн гаралт = golden `seal-visible` байт-ижил); CI 17/21 Linux/Windows.

### rp-conformance/2 (cross-SDK hardening) ба тамганы бүртгэл (`POST /seal/{orgEtsi}/registrations`)

- Юу:
  - Conformance corpus v2: `src/test/resources/conformance` = `eid-mongolia-sdk-go` `a537226` (corpus нь `704e7b1`-тэй
    байт-ижил; `scripts/sync-conformance.sh`-ийн `--check`-ээр CI тулгана). rp-validate 88/88, OCSP 24/24, wire 26/26,
    eidlogin 34/34 (harness шинэ `wireCookieName`, `cookieDomain`, `cookiePath`, `clientIp`, `auditKeyHex`, `rateLimits`,
    `cookieHeader`, `absentAttributes`-ийг хэрэгжүүлж, үл мэдэх corpus түлхүүр дээр унана).
  - Validator: `cert.weak_key` (`ValidationReasons.CERT_WEAK_KEY` — RSA < 2048 бит, эсвэл exponent тэгш / < 3) ба
    `subject.duplicate_identity` нь `cert.malformed`-ийн дараа шууд (auth, sign, certificate choice, токен нэвтрэлт,
    My QR-д `QR_CHAIN_INVALID`); issuer allowlist нь олдсон issuer-ийн SKI-г, SKI алга бол RFC 5280 арга 1-ийн key id-г
    (leaf-ийн AKI зөвхөн issuer олдоогүй үед); trust pool-д сул RSA түлхүүр → тохиргооны алдаа (`IllegalArgumentException`).
  - OCSP checker: сул RSA түлхүүртэй issuer → `no_issuer` (кэш / сүлжээнээс өмнө, AKI/SKI шалгалттай), delegated
    responder-ийн сул түлхүүр (exponent ч) → `signature`.
  - Тамганы бүртгэл (Go PR #74 / TS PR #98): `SealService.registerSealedPdf`, `sealForDocument`, `pades.SealRegistration`,
    `pades.DocumentSealer`, `SealOptions.qr / docId / fileName`, `Completed.sealRegistration()`, `EidErrorCodes.SEAL_REGISTER`
    + `SEAL_NOT_FOUND`, `SEAL_DOC_MISMATCH`, `DOC_ID_RESERVED` (төрөлжсөн `EidException.SealNotFound`, `SealDocMismatch`,
    `DocIdReserved`), `Routes.SEAL_REGISTRATIONS` (contract тест live discovery-ийн `endpoints.seal.registration`,
    `seal.registerErrorCodes`, `{docId, revIndex}`-тэй тулгана). `qr`-гүй `sealPdf` гаралт өмнөхтэй байт-ижил.
  - `EidLogin.RateRule` — `maxKeys` (`RateRule.of(max, window, maxKeys)`); 0.2.0-ийн 3 аргументтай constructor хэвээр.
- Security (интеграторт харагдах өөрчлөлт):
  - Нэвтрэх cookie-ийн анхдагч нэр `eid_login` → `__Host-eid_login` (Secure, Domain алга, Path `/` үед; бусад үед
    `eid_login` хэвээр, `cookieName(...)` өгсөн бол өөрчлөгдөхгүй). Шинэчлэх үед явагдаж буй нэвтрэлтүүд нэг удаа дахин
    эхэлнэ. Хүсэлтэд нэвтрэх cookie нэгээс олон байвал cookie-гүй гэж үзнэ (status `EXPIRED`, callback `eid_error=expired`).
  - Push rate-limit түлхүүр `push:<регистрийн дугаар>` → `push:<pushKey>` (аудитын HMAC, 32 hex): өөрийн
    `rateLimit(...)` hook / `RateRule.func` / Redis хязгаарлагч дугаар биш HMAC харна. Олон instance нэг хязгаарлагч
    хуваалцвал бүгдэд ижил `auditKey` өг (эс бөгөөс түлхүүр instance тус бүр өөр).
  - Trust pool-д (anchor / intermediate) сул RSA түлхүүртэй гэрчилгээ өгвөл `ResponseValidator` үүсэхгүй (өмнө нь
    гинжийн шалгалтад `chain.untrusted`).
- Нийтийн API зөвхөн нэмэгдсэн (0.2.0-тэй source/binary нийцтэй); reason key-ийн нэр солигдоогүй.
- Яагаад: Go / TS / .NET-тэй ижил corpus v2 ба CA V158-ийн тамганы бүртгэл.
- Шалгасан: `./gradlew build` macmini (JDK 17) дээр; CI 17/21 Linux/Windows; contract workflow (live discovery).

### ValidatePDF: гарын үсэгтэй PDF-ийг локал шалгах (`EidPades.validatePdf`)

- **Юу:** `EidPades.validatePdf(pdf, ValidatePdfOptions)` → `PdfReport` (`mn.eidmongolia.eid.pades.validate`): Go
  `pades.ValidatePDF` / TS `validatePdf`-ийн порт — ByteRange/messageDigest, CMS, signing-certificate-v2, гинж (fail-closed:
  nameConstraints / танихгүй critical extension, RSA ≥ 2048, ECDSA r/s муж), RFC 3161, гарын үсгийн дараах revision
  ангилагч (харагдах тамга APPEARANCE_SPEC §5), DSS ба онлайн OCSP/CRL, LTV, түвшин; JSON тайлан CA `/v3/validate/pdf`-тэй
  ижил. `ValidatePdfException` кодууд. Runtime хамааралгүй (гараар бичсэн PDF/DER задлагч).
- **Яагаад:** Java SDK-г Go / TS-тэй ижил хүрээтэй болгох (parity plan WP 7).
- **Хаана:** `src/main/java/mn/eidmongolia/eid/pades/validate/`, `pades/ValidateSupport.java`, `EidPades.validatePdf`;
  corpus `src/test/resources/pades-validate` (Go 67e05f1 = v0.31.0, `scripts/sync-pades-validate.sh`, CI `validate-sync`).
- **Шалгалт:** corpus 67/67 тайлан яг тэнцүү (харагдах e-Seal / QR тамга — golden v13 бичигчээр); сөрөг тест (байт
  өөрчлөх, shadow revision, итгэлгүй root, гэмтсэн бүтэц, таслалт / mutation sweep).
- **Review-ийн засвар (hostile input):** том тоон token / OID-ийн квадрат ажил, давхацсан stream-ийн хуулбар (reader /
  parser-ийн 256 MiB төсөв, DSS 1 MiB/8 MiB, кэш байтаар), xref stream-ийн өсөлт (W=0, 2^21 id, 128 section), ObjStm
  толгойг нэг удаа индекслэх, CMS 32 гэрчилгээ, serial ≤ 160 бит, RSA 2048–8192 / e ≤ 2^32−1, DSS нотолгоог нэг удаа
  шалгах, ижил гарын үсгийн толь нэг удаа; RSA-PSS параметр хатуу, SignerInfo-ийн SHA-1 алгоритм = weak; гэмтсэн
  extension зөвхөн тэр гарын үсгийг унагана; `platform_attested` зөвхөн өөрчлөгдөөгүй баримтад; тасалдал / OOM
  залгигдахгүй. **Shadow /Length:** гарын үсгийн revision-д хөдлөөгүй xref-тэй объект тэр revision-ий төгсгөлд багтах
  ёстой (TS/Go-оос хатуу) — эс бөгөөс `modified_after_signing`.

### ValidatePDF corpus v14: Go / TS-ийн хатуурлын порт (`EidPades.validatePdf`)

- Юу:
  - Corpus: `src/test/resources/pades-validate` = `eid-mongolia-sdk-go` `222acbd6e769` (v14, 80 тохиолдол: өмнөх 67 байт-ижил
    + 13 шинэ; `scripts/sync-pades-validate.sh`, CI `validate-sync` `--check`). Тайлан бүхэлдээ Go-тэй тэнцүү 80/80.
  - Хожмын гарын үсэг: зөвхөн бүрэн бүтэн (integrity) гарын үсэг «гарын үсгийн өргөтгөл» болно (Go extract.go).
  - Shadow дүрэм: xref мөр нь өөрчлөгдөөгүй объект (ба түүний ObjStm) гарын үсгийн revision-ий байт дотор бүтнээрээ
    задрах ёстой (Go revisions.go `diff`) — өмнөх final-view extent шалгалтыг сольсон.
  - Бүтцийн урьдчилсан шалгалт (Go `CheckStructure` / TS `checkStructure`): xref хэсэг ≤ 128, xref stream `/W` 0…8 ба
    мөрийн урт > 0, `/Index` start + count ≤ 2^21, нийт мөр ≤ 2^21, xref stream-д ганц шүүлтүүр (задалсан хэмжээ ObjStm-тэй
    хуваалцсан 32 MiB төсөвт), ObjStm-ийн гишүүн хайлтын ажил ≤ 1 GiB. Prepare / complete / suggest-д мөн үйлчилнэ (Go-той ижил).
  - CMS / цагийн тэмдгийн токены гэрчилгээг задалсны дараа хязгаарлана (≤ 32, serial ≤ 160 бит утгаар, RSA ≤ 8192 бит,
    e ≤ 2^32−1); TSTInfo serial-ийг утгаар; SignerInfo-ийн MD2/MD5/OIW SHA-1 алгоритм = weak; DSS-ийн давхар заалт массив
    бүрд нэг удаа.
- Security (интеграторт харагдах өөрчлөлт):
  - 128-аас олон incremental update (xref хэсэг) эсвэл маш олон object stream гишүүнтэй баримт → `PDF_INVALID` (өмнө нь
    `PDF_NO_SIGNATURE` эсвэл удаан задлал); xref stream-ийн `/W` / `/Index` хязгаараас гадуур → `PDF_INVALID`.
  - Хожмын гарын үсэг бүрэн бүтэн биш бол өмнөх гарын үсгүүд `modified_after_signing` (өмнө нь `valid` +
    `extended_by_signatures_only`).
  - CMS-д 33+ гэрчилгээ, 8192-оос том RSA модуль, 2^32−1-ээс том e, 160-аас урт serial → `malformed_signature`.
- Нийтийн API өөрчлөгдөөгүй.
- Хаана: `pades/Structure.java`, `pades/validate/{Extract,Classifier,OwnAppearance,SigMeta,VCrypto,Evaluate,PdfView}.java`;
  тест `StructureLimitsTest` (хил тус бүр), `ValidateHardeningTest` (дүрэм B, гэрчилгээний хязгаар, сул алгоритмууд).
- Шалгалт: macmini дээр `./gradlew build` — 331 тест, 0 алдаа, 0 алгассан (ValidatePdfGoldenTest 80/80); PR CI.

### ValidatePDF corpus v15: тамганы `/Name`-ийг гэрчилгээний нэртэй харьцуулахгүй (`EidPades.validatePdf`)

- Юу: v14-ийн B дүрмийн тамганы `/Name`-ийг гэрчилгээний нэртэй тулгах хэсгийг хассан (Go `9f68390` appearance.go /
  extract.go): `OwnAppearance`-ийн шалгалт, `SigMeta.name`, `Extract.certDisplayName`. Нөгөө хэсэг хэвээр — зөвхөн бүрэн
  бүтэн (integrity) хожмын гарын үсэг өргөтгөл болно. `/Name`-ийн уртын хязгаар ба тамганы бусад шалгалт хэвээр;
  тайлангийн `signer_name` гэрчилгээнээс, `claimed_name` `/Name`-ээс.
- Интеграторт харагдах: бүрэн бүтэн хожмын гарын үсгийн тамганы `/Name` гэрчилгээний нэрээс зөрсөн ч өмнөх гарын
  үсгүүд `valid` (`extended_by_signatures_only`, `visible_later_signature`). Тулгалт нь зөвхөн main дээр (v14) байсан,
  ямар ч release-д ороогүй.
- Яагаад: гаргасан eID Windows desktop клиент `/Name`-д порталын кирилл нэр бичдэг (гэрчилгээнийх латин), интегратор
  өөрийн `signerName` өгч болно — хууль ёсны давхар гарын үсэгтэй баримт өөрчлөгдсөн гэж мэдээлэгдэж байв; итгэмжлэгдээгүй
  зурагч гэрчилгээнийхээ нэрийг өөрөө сонгодог тул харьцуулалт хамгаалалт нэмдэггүй.
- Хаана: `pades/validate/{OwnAppearance,SigMeta,Extract}.java`; corpus `src/test/resources/pades-validate` =
  `eid-mongolia-sdk-go` `9f6839060115` (v15, 80 тохиолдол, зөвхөн `later-stamp-name-mismatch`-ийн хүлээгдэх тайлан өөрчлөгдсөн);
  тест `ValidateHardeningTest.laterStampNameIsNotCompared` (хуучин нэр тулгах тестийг сольсон), corpus version = 15 баталгаа.
- Шалгалт: macmini дээр `./gradlew build` — 331 тест, 0 алдаа (ValidatePdfGoldenTest 80/80); PR #17 CI.

## 0.2.0 — 2026-11-26

The full relying-party SDK in the same artifact (coordinates and `Automatic-Module-Name` `mn.eidmongolia.eid.pades`
unchanged): RP-API client, response validator with OCSP revocation, sign-in button backend, organisation / person /
e-Seal / token / share, «My QR» client, `EidPades.sealPdf` (invisible). The public API of `mn.eidmongolia.eid.pades`
0.1.1 is unchanged (additions only). Migration notes: README «Migrating from 0.1.x».

### Security

**Certificate parser inconsistency — affects 0.1.0 and 0.1.1, fixed in 0.2.0 (#7).** Every certificate was decoded
twice: by the JDK `CertificateFactory` (signature, public key, validity) and by the SDK's own DER reader (serial,
issuer and subject names — including the PNOMN identifier —, KeyUsage, EKU, qcStatements, key identifiers). When the
input did not start with a DER SEQUENCE byte, the JDK factory fell back to PEM and skipped everything before
`-----BEGIN`, so one crafted blob could show the JDK a genuine certificate and the SDK's reader different names and
extensions.

- Affected: «My QR» verification (`EidQr.verify`, the two `x5c` certificates in the JWS header) — the signer identity
  in `Result.signer()` and the leaf / issuer profile checks; PAdES `complete` — certificates embedded in OCSP responses
  (responder checks) and, for non-DER encodings only, in TSA tokens. `prepare`, the DTBS and the registration body are
  not affected.
- Precondition: an attacker must get crafted certificate bytes into one of these paths — a «My QR» JWS that the
  relying party did not take directly from its own RP-API session result, or a network position on the OCSP / TSA
  fetches during `complete` — **and** must be able to produce a valid signature over attacker-chosen data with the key
  of a genuine certificate that chains to the trusted national root (the JDK-side certificate is still fully verified).
- Fix: one certificate entry point for every package that accepts DER only — first byte 0x30, the JDK's re-encoding
  byte-identical to the input (no BER, no trailing data), and serial, issuer, subject and the extension set equal in
  both parsers.
- Action: upgrade to 0.2.0; there is no configuration workaround for 0.1.x. No exploitation is known.

Further hardening (stricter — input that 0.1.x accepted may now be rejected):

- Chain signatures must be SHA-256/384/512 (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA); SHA-1 and MD5 are rejected (an OCSP
  response's embedded responder certificate may still use SHA-1, as Go x/crypto/ocsp allows). RSA keys under 2048 bits
  are rejected (signature verification, CAs, OCSP responders).
- «My QR»: an OCSP `unknown` answer is treated as revoked (`QR_CERT_REVOKED`, was `QR_REVOCATION_UNKNOWN`), OCSP
  answers up to 48 h old are accepted (was 24 h) — the Go / TS rule; the chain is fail-closed (unknown critical
  extension, name constraints, pathLen, CA RSA ≥ 2048).
- OCSP: the response's CertID must be bound to the issuer, and the leaf must be issued by the given issuer before any
  cache or network use.
- A certificate subject with more than one SERIALNUMBER or CN is rejected (`subject.duplicate_identity`, «My QR»
  `QR_CHAIN_INVALID`).
- ECDSA signatures are range-checked (0 < r, s < n) before the JDK verifies them; empty / `.` / `..` path parameters
  are refused; the sign-in backend's deployment guidance and limits were tightened after an independent review (#10).

### Release preparation

- Version 0.2.0 (`build.gradle.kts` default; the tag still sets it for JitPack and the release workflow), POM
  description; README in three languages documents the whole RP SDK (install, client / trust / mTLS, auth push / QR +
  ticker, session, validator and revocation defaults, sign, PDF registration, organisation / person / e-Seal / token /
  share, «My QR» client, `sealPdf` (invisible only), the sign-in backend with the corrected JDK / Servlet / Spring
  examples), the support matrix against Go / TS and a migration note for 0.1.x.
- Checked: the public API of `mn.eidmongolia.eid.pades` against tag 0.1.1 (no type or member removed or changed; the
  classes moved to `mn.eidmongolia.eid.internal` were package-private); the release workflow and `jitpack.yml` need no
  change for 0.2.0.

### RP-API клиентийн суурь (`mn.eidmongolia.eid`, хийгдэж байна)

- Юу: ижил artifact-д (координат өөрчлөгдөөгүй) шинэ `mn.eidmongolia.eid` багц — `EidClient.builder(credentials)…build()`
  (baseUrl-ийн дүрэм: зөвхөн https, http нь зөвхөн loopback, хуучин `ca.eidmongolia.mn` хост алдаа; Bearer; `Duration`
  timeout, PDF 80 с; Accept-Language; JSON ≤ 4 MiB), солигддог `EidTransport` + анхдагч `JdkHttpTransport`
  (`java.net.http`, mTLS = `SSLContext`, redirect үгүй, нийт deadline, interrupt-оор цуцлах), `EidException`-ийн шатлал
  (`code`/`status`/`retryAfter`/`retryable`, кодоор дэд ангиуд), Go `routes.go`-той ижил замын хүснэгт, wire record-ууд,
  discovery `auth().sessionTtl()`; крипто туслахууд — `Acsp` (ACSP_V2 payload/digest), `EidCrypto` (interactions →
  base64 `JSON.stringify`-тай байт-ижил, sessionSecretDigest, userChallengeOf, randomChallenge), `DeviceLink.build`
  (authCode HMAC-SHA256). Дотоод `Json`-д `JSON.stringify` writer.
- Яагаад: Java SDK-г Go/TS-тэй ижил хүрээтэй RP SDK болгох эхний багц (WP 1). Auth/Sign/Session/Validator дараагийн багцад.
- Хаана: `src/main/java/mn/eidmongolia/eid/*`, тест `src/test/java/mn/eidmongolia/eid/*`, `src/test/resources/devicelink_golden.json`
  (CA-ийн засваргүй хуулбар), `.github/workflows/contract.yml`, README (гурван хэл). `pades` багцын нийтийн API өөрчлөгдөөгүй;
  runtime хамаарал нэмэгдээгүй.
- Шалгасан: device-link golden (15 вектор + 10 invalid, SHA-256 бэхэлсэн), Smart-ID ACSP_V2 вектор, interactions-ийн
  escape тохиолдлууд (Go/TS-ээс), baseUrl дүрэм, хуурамч transport-оор алдааны mapping, loopback сервертэй
  `JdkHttpTransport` (хязгаар, deadline, interrupt, redirect); CI (Linux/Windows × JDK 17/21) + live гэрээ `contract.yml`.

### RP-API: Auth, Sign, certificate choice, Session, PDF бүртгэл (`mn.eidmongolia.eid`, WP 2)

- Юу: `client.auth()` — `notificationByEtsi` / `notificationByDocument` / `deviceLinkAnonymous` / `deviceLinkByEtsi`
  (`AuthOptions`: certificateLevel, callbackUrl, onBehalfOf, signatureAlgorithm, hashAlgorithm), хариу нь validator-т
  хэрэгтэй `AcspContext`-тэй; `client.sign()` — `digestByEtsi` / `digestByDocument` / `textByEtsi` / `deviceLinkByEtsi` /
  `deviceLinkByDocument`, `digestForSigner` / `deviceLinkForSigner` (`SignerRef`, linked), `certificateChoiceByEtsi` /
  `certificateChoiceDeviceLink` (`SignOptions`, `CertChoiceOptions`), хариу нь `SignContext`-тэй; `client.session()` —
  `poll`, `waitForResult` (`WaitOptions`; хугацаа: maxWait → expiresAt → discovery sessionTtl → 600 с, + 15 с),
  `parseSessionResult` (person, onBehalfOf, tokenCertificate, presentation), `requireOk` (`SessionFailed`);
  `client.pdf().registerSignature(Registration)` — `POST /pdf/signatures`, 409 `PRIOR_MISMATCH`-ийн хослолын давталт;
  `DeviceLink.tickQr` — QR холбоосыг секунд тутам гаргах блоклогч ticker (interrupt-оор зогсоно).
- Яагаад: Java SDK-г Go/TS-тэй ижил хүрээтэй RP SDK болгох хоёр дахь багц (WP 2). Validator, OCSP, login дараагийн багцад.
- Хаана: `src/main/java/mn/eidmongolia/eid/*` (`pades` багцын нийтийн API өөрчлөгдөөгүй, runtime хамаарал нэмэгдээгүй),
  тест `src/test/java/mn/eidmongolia/eid/*`, wire векторууд `src/test/resources/wire/rp-wire-local.json`.
- Шалгасан: хуурамч transport-оор арга бүрийн HTTP method / зам / query / request-body JSON (утгаар) ба хариу/алдааны
  задрал — Go/TS тестүүдээс шилжүүлсэн векторууд (эх тест бүрд нэрлэсэн; ирээдүйн `rp-conformance-v1` корпусыг залгах
  `WireVectors.Source`), waitForResult-ийн хугацааг хуурамч цагаар, ticker-ийн гаралтыг CA-ийн device-link golden-оор;
  CI (Linux/Windows × JDK 17/21).

### RP-API: хариуны validator, trust roots, OCSP цуцлалт шалгагч, subject (`mn.eidmongolia.eid`, WP 3)

- Юу: `client.validator()` (`EidClient.Builder.trust(TrustConfig)`) = `ResponseValidator` — `validateAuth` (ACSP_V2:
  flowType relay хаалт, userChallengeVerifier, callback дүрэм, алгоритм/hash downgrade хаалт, гарын үсэг),
  `validateSign` (RAW_DIGEST: prehashed RSA-PSS salt = hLen — EMSA-PSS-VERIFY-г `BigInteger.modPow` дээр, PKCS#1 v1.5
  NONEwithRSA + DigestInfo, ECDSA P-256 NONEwithECDSA DER), `validateCertificateChoice` → `Signer` (`ref()` =
  `SignerRef`), `checkRevocation` / `checkRevocationStatus` / `checkRevocationWith`; гараар бичсэн детерминист гинж
  угсрагч (PKIX биш): `Roots` (01 + 02–04, Go/TS-тэй байт-ижил), issuer SKI allowlist, clock skew, pathLen, KU/EKU
  (EKU давхарга), fail-closed — name constraints-тэй CA ба үл таних critical extension татгалзана; түвшин
  (qcStatements, токены профайл, хариуны түвшин гэрчилгээнийхээс өндөр бол алдаа); `Subject.parse`,
  `VerifiedIdentity`, `VerifiedSignature`. `EidException.Validation.reason()` нь одоо корпусын тогтвортой түлхүүр
  (`ValidationReasons`, ж: `chain.untrusted`), текст нь `detail()`. Нийтийн `OcspRevocationChecker` (Go
  `NewOCSPChecker`): unknown → revoked, thisUpdate ∈ [now − 48 ц, now + 5 мин], кэш min(5 мин, nextUpdate), 2 с /
  нийт 3 с, хариу ≤ 16 KiB, redirect үгүй, delegated responder (id-kp-OCSPSigning) шалгалт; хариугүй үед
  `EidException.Ocsp` (`kind()`).
- Засвар (зан өөрчлөгдөнө): «Миний QR»-ийн анхдагч цуцлалт (`EidQr.verify`, `Trust.revocation` = null) одоо дээрх
  шалгагчаар — OCSP `unknown` → `QR_CERT_REVOKED` (өмнө нь `QR_REVOCATION_UNKNOWN`), thisUpdate-ийн цонх 48 ц (өмнө нь
  PAdES LTV-ийн 24 ц), timeout 2 с / 3 с (өмнө нь 10 с). Go/TS-ийн дүрэмтэй ижил. PAdES LTV-ийн 24 ц дүрэм өөрчлөгдөөгүй.
- Аюулгүйн засвар (0.1.x-д мөн хамаарна — «Миний QR» ба PAdES): гэрчилгээг хоёр задлагч өөр байтаар уншиж болдог байв
  — JDK `CertificateFactory` эхний байт 0x30 биш үед PEM гэж уншиж «-----BEGIN»-ээс өмнөхийг алгасдаг тул хуурамч
  оролт JDK-д жинхэнэ гэрчилгээ (гарын үсэг, түлхүүр, хугацаа), гар задлагчид өөр TBS (subject/PNOMN, EKU,
  qcStatements) харуулна. Одоо гэрчилгээний цорын ганц орц `Cert.parse` (бүх багц): эхний байт 0x30, JDK-ийн
  `getEncoded()` оролттой байт-ижил (BER / илүү байт үгүй), serial / issuer / subject / extension-ийн олонлог хоёр
  задлагчид ижил. Гинжийн гарын үсэг зөвхөн SHA-256/384/512 (RSA PKCS#1 v1.5, RSASSA-PSS, ECDSA) — SHA-1 / MD5
  татгалзана (OCSP-ийн шигтгэсэн responder-т x/crypto-гийн дүрмээр SHA-1 зөвшөөрнө, MD5 үгүй); RSA түлхүүр ≥ 2048
  (гарын үсэг шалгах, CA, OCSP responder); хоосон `userChallengeVerifier`-ийг ч тулгана (TS дүрэм); «Миний QR»-ийн
  гинжинд validator-ийн fail-closed дүрэм (үл таних critical extension, name constraints, pathLen, CA RSA ≥ 2048), OCSP-д
  CertID issuer-hash холбоос (`OcspRevocationChecker.Builder.bindCertId`); null талбартай гараар хийсэн record →
  `Validation` (NPE биш); OCSP observer кэшийн lock-ийн гадна.
- Дараагийн cross-SDK ажил (энэ PR-т биш): давхардсан SERIALNUMBER/CN-тэй гэрчилгээг бүх SDK-д татгалзах + corpus
  кейс; RP OCSP шалгагчид CertID hash-ийн тулгалт (Go/TS/.NET); issuer allowlist-ийн AKI fallback.
- Дотоод: DER / X.509 / signature-by-OID / ASN.1 time / OCSP туслахууд `mn.eidmongolia.eid.internal` багц руу шилжив
  (pades ба RP client хуваалцана; `pades`-ийн нийтийн API өөрчлөгдөөгүй). JSON уншигч хоёр хэвээр (бичигч нь өөр —
  Go-escape vs JS stringify).
- Яагаад: Java SDK-г Go/TS-тэй ижил хүрээтэй RP SDK болгох гурав дахь багц (WP 3); аюулгүйн гол давхарга.
- Хаана: `src/main/java/mn/eidmongolia/eid/*` (validator, OCSP, Roots, TrustConfig, …), `…/internal/*`,
  `…/pades/EidQr.java`; corpus `src/test/resources/conformance` (Go commit `a0b00e2`, `scripts/sync-conformance.sh`,
  CI `conformance-sync`).
- Шалгасан: cross-SDK conformance corpus `rp-conformance/1` бүхэлдээ — rp-validate 77 кейс (identity/түвшин эсвэл
  алдааны анги + reason түлхүүр, тогтмол цаг), OCSP 17 сценари (HTTP replay), wire 26, interactions 8, ACSP 3,
  manifest-ийн SHA-256; PSS known-answer + JCA RSASSA-PSS-тэй тулгалт; CI (Linux/Windows × JDK 17/21).

### RP-API: байгууллага, иргэний PKI, e-Seal, токен, share, «Миний QR» client, SealPDF (`mn.eidmongolia.eid`, WP 5)

- Юу: `client.organization()` (`getRepresentations`, `sealGrants`); `client.person()` (PKI_READ: `certificates`,
  `devices`, `activity(ActivityQuery)`, `summary`, `children`); `client.seal()` (`certificate`, `requestCertificate`,
  `certificateRequest`, `waitForCertificate`, `requestGrant`, `grantStatus`, `waitForGrant`, `seal(org, digest, hash)` —
  хариуны ECDSA гарын үсгийг e-Seal гэрчилгээгээр digest дээр шалгана; `seal(…, docId, revIndex)` — CA V158-ийн
  заавал биш талбар, Go/TS-д хараахан алга; `isSealCertificate`); `client.token()` (`issueCertificate`,
  `previewCertificate`, `certificateResult`, `certificateInfo`, `authChallenge`, `authVerify` — CA руу илгээхээс өмнө
  rpUUID, r‖s гарын үсэг, гэрчилгээг validator-ийн гинжээр шалгана; static `verifyTokenCertificates`,
  `tokenAuthDigest`, `tokenLimitOf`); `client.share(ShareRequest)` (multipart, Go mime/multipart-тай байт-ижил бүтэц,
  `EidException.Share`) ба `client.shareInfo()`; `client.qr()` (`start`, `result`, `check`, `verify` — шалгалт нь
  `EidQr.verify`; `Builder.qrTrust` / `qrIssuer`); `EidPades.sealPdf(Sealer, org, pdf, SealOptions)` (`SealService`
  нь `Sealer`). Алдаа: `EidException.SealRequestFailed`, `SealGrantFailed`, `Share`; `EidErrorCodes.TOKEN`, `SHARE`;
  `EidQrException.TOKEN_INVALID` / `PENDING` / `PRESENTATION_GONE` (+ нийтийн cause-тай constructor).
- SealPDF энэ хувилбарт зөвхөн үл харагдах (`SealOptions.invisible(true)`, Go `Invisible: true`-тэй ижил гаралт):
  PAdES хөдөлгүүр golden v11 дээр — тамганы дардас (v12) ба QR-тэй тамга + docId дүрэм (v13) тусдаа PR-ээр;
  `invisible(false)` (анхдагч) → REQUEST_INVALID, сүлжээгүй.
- Аюулгүйн чангаруулалт (Go/TS-ээс хатуу, cross-SDK): `OcspRevocationChecker` leaf-ийг өгсөн issuer гаргасан эсэхийг
  кэш ба сүлжээнээс ӨМНӨ шалгана (үгүй бол `no_issuer`), CertID issuer-hash холбоос анхдагчаар асаалттай
  (`bindCertId(false)`-оор Go/TS-ийн дүрэм) — corpus-ийн 17 OCSP кейс ногоон; subject-д SERIALNUMBER эсвэл CN нэгээс
  олон бол validator `subject.duplicate_identity` (шинэ тогтвортой түлхүүр), «Миний QR» `QR_CHAIN_INVALID`.
- Яагаад: Java SDK-г Go/TS-тэй ижил хүрээтэй RP SDK болгох тав дахь багц (WP 5).
- Хаана: `src/main/java/mn/eidmongolia/eid/{Organization,Person,Seal,Token,Share,Qr}Service.java` + DTO record-ууд,
  `…/pades/{Sealer,SealOptions,EidPades}.java`, `OcspRevocationChecker.java`, `ResponseValidator.java`.
- Шалгасан: fake transport-оор арга бүр (method, path, бие семантикаар, хариу задлалт, алдааны ангилал; Go/TS тестийн
  нэр тест бүрд), «Миний QR» CA векторууд (`myqr_vectors.json`), `docs/TOKEN_AUTH.md` digest вектор, multipart-ийн
  байт бүтэц, SealPDF урсгал (complete гарын үсгийг хүлээн авч TSA хүртэл), contract тестэд share/token блок; CI.

### «eID-ээр нэвтрэх» товчны backend (`mn.eidmongolia.eid.login`, WP 4)

- Юу: framework-аас хамааралгүй `EidLogin` (`handle(EidLoginRequest) → EidLoginResponse`, Go `eidlogin.Handler` / TS
  `createEidLogin` + `handleRequest`) — `start` (qr | push | GET web2app → 302), `status` (PENDING + шинэ QR |
  WAIT_CALLBACK | OK | FAILED | EXPIRED), `callback` (Web2App, userChallengeVerifier, 303); HttpOnly + Secure +
  SameSite=Lax cookie `<sessionId>.<binding>` (binding-ийн SHA-256 серверт, constant-time тулгалт); `EidLoginStore`
  (анхдагч санах ой: TTL, 10 000 дээд, дүүрвэл шинэ нэвтрэлтийг 503 busy); rate limit (start: IP тутам 60 с-д 20, push:
  дугаар тутам 60 с-д 3; `rateLimits` / `rateLimit` hook; дүүрсэн хязгаарлагч fail-closed); клиент IP — адаптер эсвэл
  `forwardedClientIp(n)` (зөвхөн итгэмжит proxy); push decoy (eID-ийн JSON 4xx → бодиттой ижил хэлбэр), push хариуны
  доод хугацаа (1 с), discovery `sessionTtl.auth`-аар push TTL; OCSP цуцлалт core `OcspRevocationChecker`-ээр
  (soft-fail анхдагч); `onSuccess` (ШИНЭ session-ий Set-Cookie-г headers-ээр), `onEvent` аудит (PII-гүй, pushKey =
  HMAC); алдааны кодууд ба HTTP статус Go/TS-тэй ижил. JDK `com.sun.net.httpserver` адаптер `EidLoginHttpHandler`
  (`ClientIp.direct()` / `trustedProxies(n)` / `none()`); README-д Servlet / Spring жишээ. Шинэ runtime dependency үгүй.
- Яагаад: Java SDK-г Go/TS-тэй ижил хүрээтэй RP SDK болгох дөрөв дэх багц (WP 4).
- Хаана: `src/main/java/mn/eidmongolia/eid/login/*`, README (mn/en/zh).
- Шалгасан: conformance `eidlogin/scenarios.json`-ийн 24 сценари бүгд (статус, JSON, header, Set-Cookie шинж, event,
  rate-limit түлхүүр; manifest-ийн SHA-256); Go `security_test.go`-ийн корпуст ороогүй тохиолдлууд — хуурмаг цаг дээрх
  push floor, conformance PKI-ийн жинхэнэ ACSP_V2 гарын үсэгтэй OK зам (QR ба Web2App callback), цуцлалтын үр дүн,
  store-ийн дээд хэмжээ, session fixation, cross-site, дууссан нэвтрэлтийн replay; loopback дээрх JDK HttpServer тест; CI.

### Хараат бус security review-ийн засвар: нэвтрэлтийн backend ба үйлчилгээнүүд

- Юу:
  - JDK `HttpServer` adapter (`EidLoginHttpHandler`): Javadoc ба README (mn/en/zh)-ийн жишээ `setExecutor`-тэй
    (Java 21+ `Executors.newVirtualThreadPerTaskExecutor()`, Java 17 хязгаартай pool), `sun.net.httpserver.maxReqTime` /
    `maxRspTime` (секунд) эсвэл reverse proxy; executor-гүй сервер дээр нэг удаагийн анхааруулга. Биеийн уншилтад
    deadline тавих боломж exchange API-д алга (socket timeout өгдөггүй) — хязгаар 4 KiB + 1 хэвээр, deadline-ийг JVM
    тохиргоо / proxy-оор баримтжуулав.
  - README snippet: Spring нь `@RequestBody byte[]`-ийн оронд `readNBytes(4097)`; клиент IP-ийн жишээ хоёр тусдаа,
    бие биенээ үгүйсгэх хувилбар (proxy-гүй / N итгэмжит proxy) + анхааруулга (builder-ийн `clientIp` adapter-ийнхийг дарна).
  - `status`: нэвтрэлт тутамд single-flight — ижил session-ий зэрэг ирсэн status шууд PENDING (thread барихгүй).
  - Push-ийн TTL (`authTtl`): discovery-г 2 с-ийн deadline-тэй (Go-той адил; шинэ `AuthService.sessionTtl(Duration)`),
    түгжээг сүлжээний дуудлагын үед барихгүй, refresh single-flight.
  - Клиент IP: ямар ч эх сурвалжгүй бол нэг удаа анхааруулга (корпус «IP-гүй → хязгааргүй»-г бэхэлсэн тул тэр зан төлөв
    хэвээр); builder-ийн `clientIp` хоосон буцаавал / adapter хаяг гаргаж чадаагүй бол хуваалцсан `start:unknown` хувин;
    IPv6 /64-өөр; хязгаарлагчийн хүснэгт дүүрвэл шинэ түлхүүр overflow хувинд (өмнө нь бүгдийг татгалздаг байсан;
    байгаа тоолуур хэзээ ч цэвэрлэгдэхгүй). Дугаар тутмын push хязгаар хохирогчийн push нэвтрэлтийг хойшлуулж болохыг
    баримтжуулав (QR / Web2App-д нөлөөгүй).
  - ECDSA: `Sig.ecdsaInRange` / `ecdsaDerInRange` (internal) — 0 < r, s < n-ийг JDK-д өгөхөөс өмнө (CVE-2022-21449
    ангийн алдаанаас хамгаалалт): `TokenService` r‖s, `SealService`, validator `NONEwithECDSA` (`Prehashed`), PAdES
    CMS / OCSP / CRL / TSA (`Sig.verify`), гинжийн ECDSA гарын үсэг (`Cert`).
  - `EidLoginRequest.toString()` Cookie, бие, query-г нууна; замын параметр хоосон / "." / ".." бол
    `IllegalArgumentException` (бүх үйлчилгээ); callback-ийн store алдаа 303 `eid_error=internal` (Go шиг, JSON 500 биш);
    `revIndex` 1…16 (CA-ийн хязгаар) клиент талд (`registerSignature`, `seal`).
  - Давхардсан subject-ийн шалтгааны түлхүүр .NET-тэй нэгдэв: `cert.subject_ambiguous` → `subject.duplicate_identity`
    (`ValidationReasons.SUBJECT_DUPLICATE_IDENTITY`; гаргаагүй хувилбар). Корпус (rp-conformance)-д нэмэх шаардлагатай.
- Хойшлуулсан (бүх SDK-д, эхлээд корпусын өөрчлөлт хэрэгтэй): `__Host-` cookie угтвар + давхар нэвтрэлтийн cookie-г
  татгалзах; rate-limit түлхүүрт дугаарыг hash-лах.
- Яагаад: нэвтрэлтийн backend ба үйлчилгээний хараат бус security review (дүгнэлт: засвартайгаар гаргах; логик
  тойрох зам олдоогүй; блоклогч нь adapter ба баримтжуулсан deployment).
- Хаана: `login/EidLogin.java`, `login/EidLoginHttpHandler.java`, `login/EidLoginRequest.java`, `AuthService`,
  `Routes`, `PdfService`, `SealService`, `TokenService`, `Prehashed`, `internal/Sig.java`, `internal/Cert.java`,
  `ValidationReasons`, README (mn/en/zh).
- Шалгасан: `eidlogin/1` корпусын 24 сценари; шинэ тест — N зэрэг status → onSuccess яг нэг удаа ба single-flight,
  Web2App callback хоосон / байхгүй verifier → татгалзсан (EidLogin `unbound` + validator `AUTH_VERIFIER_REQUIRED`),
  IP хувин / IPv6 / overflow, toString нууцлал, callback store алдаа, ECDSA r/s хязгаар (0, n, сөрөг, илүү байт), замын
  параметр ба revIndex; adapter тест executor-тэй, удаан клиент бусдыг блоклохгүй. macmini `./gradlew build`; CI.

### README гурван хэлтэй

- Юу: `README.en.md` (English), `README.zh-CN.md` (简体中文) — `README.md`-ийн бүрэн орчуулга (код блок, тушаал, нэр, URL, хувилбар хэвээр); гурван файлын дээр хэлний сонголтын мөр. `README.md`-ийн «English summary» хэсгийг `README.en.md` руу заасан нэг мөрөөр сольсон.
- Яагаад: орчуулга бүрэн орсон тул хураангуй хэрэггүй болсон. Хаана: зөвхөн README файлууд — код өөрчлөгдөөгүй.
- Шалгасан: код блокуудыг эх README-тэй `diff`-ээр харьцуулсан; CI-ийн PR pipeline-аар батална.

### README: кодын жишээний коммент орчуулсан

- Юу: `README.en.md`, `README.zh-CN.md` дахь кодын жишээнүүдийн монгол коммент ба дэлгэцэнд харагдах жишээ мөр (reason, fileName, displayText г.м.)-ийг тус тусын хэл рүү орчуулсан. Танигч, API нэр, протоколын утга (`"mn"`, URL, хувилбар), бүтэц хэвээр; `README.md` өөрчлөгдөөгүй.
- Яагаад: орчуулсан хуудсуудын код нь монгол коммент үлдээсэн тул хагас орчуулагдсан байсан.
- Шалгасан: кодын мөр бүрийн комментоос өмнөх хэсэг (мөр утгаас бусад) `README.md`-тэй ижил эсэхийг скриптээр тулгасан; CI-ийн PR pipeline-аар батална.

## 0.1.1 — 2026-11-25

### Fix — LTV order by certificate role (Go golden v11), Gregorian ASN.1 times, «My QR» exp overflow

- **LTV / DSS (bytes change):** CA certificates (04/03/02) now fetch their CRL first and send no OCSP request when that CRL is valid; end entities (citizen, TSA) still ask OCSP first, then the CRL. A CA OCSP responder that accepts the connection and never answers no longer holds `complete` 2 × 10 s. The DSS drops the 04 OCSP response — byte-identical to Go `pades-golden-v11` (vendored vectors bumped from v9; post-v11 Go additions are seal-only). An interrupted caller now gets `InterruptedIOException` (flag kept) instead of a missing-revocation error. `Ltv.java`, test `LtvOrderTest` (records every request; the golden replay alone cannot see an extra OCSP request).
- **ASN.1 time:** `Asn1Time` used `Calendar.getInstance(zone)`, which follows the default locale — under `th_TH` (Buddhist) or `ja_JP_JP` every TSA genTime / OCSP / CRL time was off by centuries and `complete` failed with `TSA_UNAVAILABLE`. Now a Gregorian calendar with `Locale.ROOT`. `Tsa.java`, test `V4Test.asn1TimeIgnoresDefaultLocale`.
- **«My QR»:** `(exp + 60) * 1000` overflowed for |exp| > ~9.2e15, so a far-past `exp` read as unexpired; compared in seconds now (Go `QR_EXPIRED`). `EidQr.java`, test `QrTest.farPastExpIsExpired`.
- **Hostile PDFs (parser):** a stream whose `/Length` refers to itself (or two streams to each other) recursed until `StackOverflowError`, which escaped `prepare`/`suggestPlacement` as an `Error` — re-entry now fails as `PdfException` and the stream is read up to `endstream` (Go resolves `/Length` lazily). `/Key value /Key null` now drops the key (last duplicate wins, as Go and `Structure`), so a `/Filter null` duplicate can no longer make `Structure` skip the inflate budget while the reader inflates. Xref-stream `/Index` rows with ids ≥ 2^21 (the `/Size` limit) are ignored instead of allocating one entry per hostile row. Prior-signature `/ByteRange` values are bounded one by one before the sum (long overflow + `(int)` truncation). `isVerifyPage` returns false when any annotation is unreadable (Go `recover`). `PdfReader.java`, `PdfLexer.java`, `Precheck.java`, `Appearance.java`, test `ParserHardeningTest`.
- Verified in CI only (golden byte identity, Linux/Windows, Java 17/21).

## 0.1.0 — 2026-11-25

### Added — анхны хувилбар: eID Mongolia PAdES + «Миний QR» Java (JVM) SDK

- **Юу:** `mn.eidmongolia.eid.pades` — цэвэр Java 17, runtime хамааралгүй (BouncyCastle, Jackson, Kotlin үгүй).
  `EidPades.prepare` (verify хуудас, харагдах гарын үсэг + байршил, PRECHECKS) → 32 байт DTBS; `EidPades.complete`
  (RFC 3161 TSA + OCSP/CRL + DSS → PAdES B-LT, анхдагч HTTP 10 с нийт deadline); `EidPades.suggestPlacement`;
  `Completed.registration(...)` → `POST /pdf/signatures` бие (`Registration.toJson()`, medium PHONE/TOKEN дүрэм).
  `EidQr.parse` / `EidQr.verify` — «Миний QR» PS256 JWS шалгалт (гэрээ `myqr-2026-10-26`). RP-API клиент байхгүй.
- **Яагаад:** server-side JVM RP-уудад native PAdES порт (.NET SDK-ийн JVM хос).
- **Хаана:** Android Kotlin портоос (`eid-mongolia-sdk-android` 0.10.0) Java руу; бүтцийн шалгалт (PRECHECKS #2a/#2b) нь
  Go reference-ийн 2026-11-04-ний ObjStm хатуурууллыг (offset арифметик, олон шүүлтүүр, `/Filter` доторх лавлагаа) давтана.
  QR шалгалт — .NET SDK-ийн `EidQr`-аас.
- **Шалгасан:** CI (ubuntu + windows, Java 17 + 21): Go golden `pades-golden-v9`-ийн бүх кейс байт-ижил (prepare:
  digest/DTBS/signedAttrs/prepared PDF; complete: гаралтын PDF-ийн sha256), placement vectors (29), validate v4,
  алдааны кодууд, CA-ийн `myqr_vectors.json` (sha256 бэхэлсэн).
