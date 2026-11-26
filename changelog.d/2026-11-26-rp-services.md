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
