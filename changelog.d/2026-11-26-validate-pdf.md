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
