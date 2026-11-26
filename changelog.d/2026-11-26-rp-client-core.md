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
