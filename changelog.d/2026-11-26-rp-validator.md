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
