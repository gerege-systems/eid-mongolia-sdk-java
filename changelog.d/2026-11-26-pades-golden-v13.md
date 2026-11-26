### PAdES golden v11 → v13: байгууллагын тамганы дардас, QR-тэй тамга, docId дүрэм; `sealPdf` харагдах

- Юу:
  - Go reference (`eid-mongolia-sdk-go` `499aa5c`, golden v12 + v13 + §6.6 засварууд) байт-ижил порт: e-Seal гэрчилгээтэй
    харагдах гарын үсэг нь QR-гүй тамганы дардас (APPEARANCE_SPEC §6.2: тамганы label, үүргийн мөргүй, бүтэн өргөнтэй
    бичвэр); QR-тэй тамганы дардас (§6.5) — Go-той адил нийтийн бус (`PrepareOptions` дотоод `sealQr`, зөвхөн golden).
  - `prepare`-ийн docId дүрэм (§6.6, PRECHECKS): гарын үсэгтэй баримтад verify хуудас → шалгасан e-Seal гарын үсгийн хамгийн
    эрт зурсан `/EIDVerify` тэмдэгтэй дардас (шууд бус `/V`, ганц widget, маркерын rev = байрлал, `/Filter` алга/шууд null)
    → `PrepareOptions.docId`; олдсонтой зөрвөл `REQUEST_INVALID` (үл харагдах гарын үсэгт ч); санамсаргүй docId үүсгэхгүй.
  - `EidPades.sealPdf` (Go `SealPDF`): анхдагч нь харагдах тамганы дардас (автомат ≤ 220 × 64 pt баруун доод буланд,
    багтахгүй / `PDF_TOO_LARGE` бол үл харагдах), шинэ `SealOptions.appearance`, `Completed.placement()`,
    `EidPades.SEAL_STAMP_WIDTH/HEIGHT/MARGIN`. `invisible(true)` гаралт 0.2.0-тэй байт-ижил.
  - `wrapLimit` maxLines-аас цааш мөр үүсгэхгүй (Go `vpage.go`; гаралт ижил, урт бичвэрт квадрат хугацаагүй).
  - `scripts/sync-pades-golden.sh` нь commit SHA-аар pin хийнэ (Go репод v12/v13 tag алга); `golden/SOURCE` = `499aa5c…`.
- Зан төлөвийн өөрчлөлт: `sealPdf`-ийн анхдагч `REQUEST_INVALID` → харагдах дардас; гарын үсэгтэй баримтын docId нь
  тамганы QR-тэй дардсаас ч уншигдана. Нийтийн API зөвхөн нэмэгдсэн (0.2.0-тэй source/binary нийцтэй).
- Яагаад: Java PAdES хөдөлгүүрийг Go / .NET-тэй ижил golden-д хүргэж, «зөвхөн үл харагдах» хязгаарыг авах.
- Шалгасан: `./gradlew build` macmini (JDK 17) дээр — 198 тест ногоон (golden 54 тохиолдол — 50 complete хүртэл, шинэ `SealStampTest` 12:
  Go-ийн TestSealQRContent, TestResolveDocID, TestDocIDFromStamps*, TestPrepareDocIDRule, TestSealPDF* портууд, `sealPdf`
  анхдагчийн гаралт = golden `seal-visible` байт-ижил); CI 17/21 Linux/Windows.
