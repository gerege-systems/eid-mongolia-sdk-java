# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

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
