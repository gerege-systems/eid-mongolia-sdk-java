### ValidatePDF corpus v15: тамганы `/Name`-ийг гэрчилгээний нэртэй харьцуулахгүй (`EidPades.validatePdf`)

- Юу: v14-ийн B дүрмийн «own-signer харагдах тамганы `/Name` = гэрчилгээний харуулах нэр» хэсгийг хассан (Go
  `9f68390` appearance.go / extract.go): `OwnAppearance`-ийн шалгалт, `SigMeta.name`, `Extract.certDisplayName`.
  Нөгөө хэсэг хэвээр — зөвхөн бүрэн бүтэн (integrity) хожмын гарын үсэг өргөтгөл болно. `/Name`-ийн уртын хязгаар ба
  тамганы бусад шалгалт хэвээр; тайлангийн `signer_name` гэрчилгээнээс, `claimed_name` `/Name`-ээс.
- Интеграторт харагдах: бүрэн бүтэн хожмын гарын үсгийн тамганы `/Name` гэрчилгээний нэрээс зөрсөн ч өмнөх гарын
  үсгүүд `valid` (`extended_by_signatures_only`, `visible_later_signature`) — v14-д `modified_after_signing` байсан.
- Яагаад: гаргасан eID Windows desktop клиент `/Name`-д порталын кирилл нэр бичдэг (гэрчилгээнийх латин), интегратор
  өөрийн `signerName` өгч болно — хууль ёсны давхар гарын үсэгтэй баримт өөрчлөгдсөн гэж мэдээлэгдэж байв; итгэмжлэгдээгүй
  зурагч гэрчилгээнийхээ нэрийг өөрөө сонгодог тул харьцуулалт хамгаалалт нэмдэггүй.
- Хаана: `pades/validate/{OwnAppearance,SigMeta,Extract}.java`; corpus `src/test/resources/pades-validate` =
  `eid-mongolia-sdk-go` `9f6839060115` (v15, 80 тохиолдол, зөвхөн `later-stamp-name-mismatch`-ийн хүлээгдэх тайлан өөрчлөгдсөн);
  тест `ValidateHardeningTest.laterStampNameIsNotCompared` (хуучин нэр тулгах тестийг сольсон), corpus version = 15 баталгаа.
- Шалгалт: macmini дээр `./gradlew build`; PR CI.
