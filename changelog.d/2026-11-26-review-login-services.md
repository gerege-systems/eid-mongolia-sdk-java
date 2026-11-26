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
