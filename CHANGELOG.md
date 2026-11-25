# Changelog

Бүх өөрчлөлт `changelog.d/`-ээр орж, release бүрд энд нэгтгэгдэнэ.

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
