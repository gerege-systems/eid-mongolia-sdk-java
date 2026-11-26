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
