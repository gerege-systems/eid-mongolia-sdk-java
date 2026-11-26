### ValidatePDF corpus v14: Go / TS-ийн хатуурлын порт (`EidPades.validatePdf`)

- Юу:
  - Corpus: `src/test/resources/pades-validate` = `eid-mongolia-sdk-go` `222acbd6e769` (v14, 80 тохиолдол: өмнөх 67 байт-ижил
    + 13 шинэ; `scripts/sync-pades-validate.sh`, CI `validate-sync` `--check`). Тайлан бүхэлдээ Go-тэй тэнцүү 80/80.
  - Хожмын гарын үсэг: зөвхөн бүрэн бүтэн (integrity) гарын үсэг «гарын үсгийн өргөтгөл» болно; own-signer тамганы `/Name`
    тэр гарын үсгийн гэрчилгээний харуулах нэртэй (GIVENNAME SURNAME, эс бөгөөс CN) яг тэнцүү байх ёстой (Go extract.go,
    appearance.go).
  - Shadow дүрэм: xref мөр нь өөрчлөгдөөгүй объект (ба түүний ObjStm) гарын үсгийн revision-ий байт дотор бүтнээрээ
    задрах ёстой (Go revisions.go `diff`) — өмнөх final-view extent шалгалтыг сольсон.
  - Бүтцийн урьдчилсан шалгалт (Go `CheckStructure` / TS `checkStructure`): xref хэсэг ≤ 128, xref stream `/W` 0…8 ба
    мөрийн урт > 0, `/Index` start + count ≤ 2^21, нийт мөр ≤ 2^21, xref stream-д ганц шүүлтүүр (задалсан хэмжээ ObjStm-тэй
    хуваалцсан 32 MiB төсөвт), ObjStm-ийн гишүүн хайлтын ажил ≤ 1 GiB. Prepare / complete / suggest-д мөн үйлчилнэ (Go-той ижил).
  - CMS / цагийн тэмдгийн токены гэрчилгээг задалсны дараа хязгаарлана (≤ 32, serial ≤ 160 бит утгаар, RSA ≤ 8192 бит,
    e ≤ 2^32−1); TSTInfo serial-ийг утгаар; SignerInfo-ийн MD2/MD5/OIW SHA-1 алгоритм = weak; DSS-ийн давхар заалт массив
    бүрд нэг удаа.
- Security (интеграторт харагдах өөрчлөлт):
  - 128-аас олон incremental update (xref хэсэг) эсвэл маш олон object stream гишүүнтэй баримт → `PDF_INVALID` (өмнө нь
    `PDF_NO_SIGNATURE` эсвэл удаан задлал); xref stream-ийн `/W` / `/Index` хязгаараас гадуур → `PDF_INVALID`.
  - Хожмын гарын үсгийн харагдах тамганы `/Name` гэрчилгээний нэрээс ялгаатай, эсвэл тэр гарын үсэг бүрэн бүтэн биш бол
    өмнөх гарын үсгүүд `modified_after_signing` (өмнө нь `valid` + `extended_by_signatures_only`).
  - CMS-д 33+ гэрчилгээ, 8192-оос том RSA модуль, 2^32−1-ээс том e, 160-аас урт serial → `malformed_signature`.
- Нийтийн API өөрчлөгдөөгүй.
- Хаана: `pades/Structure.java`, `pades/validate/{Extract,Classifier,OwnAppearance,SigMeta,VCrypto,Evaluate,PdfView}.java`;
  тест `StructureLimitsTest` (хил тус бүр), `ValidateHardeningTest` (дүрэм B, гэрчилгээний хязгаар, сул алгоритмууд).
- Шалгалт: macmini дээр `./gradlew build` — 331 тест, 0 алдаа, 0 алгассан (ValidatePdfGoldenTest 80/80); PR CI.
