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
