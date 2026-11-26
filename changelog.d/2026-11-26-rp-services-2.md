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
