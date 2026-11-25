[Монгол](README.md) · [English](README.en.md) · 中文

# eid-mongolia-sdk-java

**eID Mongolia** client-side PAdES——Java（JVM，服务端）SDK。PDF 文档**绝不会发送到 eID 服务器**：
在您自己的后端准备文档（`prepare`），只让公民的手机或 USB 令牌对 32 字节的 hash（DTBS）签名，
然后将签名嵌入 PDF（`complete`）。输出为 PAdES-BASELINE-LT（RFC 3161 时间戳、OCSP/CRL、DSS）。

这是 Go reference（[eid-mongolia-sdk-go](https://github.com/gerege-systems/eid-mongolia-sdk-go) 的 `pades`，profile
`pades-client/1`）的 **native Java 移植版**——CI 在 Linux 和 Windows（Java 17、21）上验证其输出与 Go 的 golden vector（verify 页、QR、xref、CMS、TSA/OCSP/CRL
请求、DSS）**字节完全一致**。

完整文档：<https://developer.eidmongolia.mn/#overview>。

- Java 17+，**无运行时依赖**——`java.security` + 一个小型 DER writer（不使用 BouncyCastle、Jackson、Kotlin）。
- 线程安全，无全局状态。仅在 `complete`（TSA、OCSP/CRL）以及 `EidQr.verify` 的默认 OCSP 中使用网络。
- **这里没有 RP-API 客户端。** 发起公民 session、获取 `RAW_DIGEST_SIGNATURE` 签名、`POST /pdf/signatures`、
  `POST /authentication/qr` 等，都需直接通过 HTTPS/JSON 调用 RP-API——
  [RP-API 文档](https://developer.eidmongolia.mn/#overview)。本库只负责准备/嵌入 PDF、组装登记请求体，
  以及解析/验证“我的 QR”。
- **没有**完整的验证器（validator）——验证：通过文件的 SHA-256 在 CA 的登记中查询；完整的密码学验证在 Go
  后端 SDK 中。

其他 SDK：[Go](https://github.com/gerege-systems/eid-mongolia-sdk-go) ·
[.NET](https://github.com/gerege-systems/eid-mongolia-sdk-dotnet) ·
[Android](https://github.com/gerege-systems/eid-mongolia-sdk-android) ·
[Swift](https://github.com/gerege-systems/eid-mongolia-sdk-swift) ·
[Node.js/TypeScript](https://github.com/gerege-systems/eid-mongolia-sdk)。

## 安装（JitPack）

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        mavenCentral()
        maven("https://jitpack.io")
    }
}

// build.gradle.kts
dependencies {
    implementation("com.github.gerege-systems:eid-mongolia-sdk-java:0.1.1")
}
```

Maven：

```xml
<repositories>
  <repository><id>jitpack.io</id><url>https://jitpack.io</url></repository>
</repositories>
<dependency>
  <groupId>com.github.gerege-systems</groupId>
  <artifactId>eid-mongolia-sdk-java</artifactId>
  <version>0.1.1</version>
</dependency>
```

版本：最新的 tag（[releases](https://github.com/gerege-systems/eid-mongolia-sdk-java/releases)——jar 也会附加在
每个 release 中）。

## 流程

```java
import mn.eidmongolia.eid.pades.*;

// 1. 准备——无需网络。signerCert = 公民的 SIGN 证书（来自 RP-API 的 session 响应，DER 格式）。
Prepared prepared = EidPades.prepare(pdf, PrepareOptions.builder(signCertDer)
        .reason("合同已确认")
        .claimedRole(claimedRole)           // 以组织名义签名时使用（来自 RP-API 的 representation 响应），否则为 null
        .verifyPage(true)                   // 验证（QR）页——仅用于第一个 eID 签名
        // .verifyPagePosition("first")     // QR 页成为第 1 页（默认 "last"）
        .fileName("合同第1号.pdf")           // verifyPage = true 时必须提供
        .lang("mn")                         // mn（默认）| en
        // 可选的可见签名：单位 pt，自页面可见的左下角起算；page 0 = 最后一页，而不是 eID verify 页
        // 高度 ≥ 45 pt；放不下则为 REQUEST_INVALID。null = 不可见。
        .appearance(new SignatureAppearance(36, 36, 220, 64))
        .build());
// prepared.placement()——可见签名的最终位置（见下文“位置”）。

// 2. 将 prepared.dtbs()（32 字节）交给 RP-API 的 signature session（RAW_DIGEST_SIGNATURE），由手机签名，或
//    使用 USB 令牌（PKCS#11）签名。等待期间可以保存 prepared.state()（格式与 Go reference 相同）。

// 3. 嵌入——使用 TSA、OCSP/CRL 网络（阻塞——请在 worker 线程上执行）。签名：RSA PKCS#1 v1.5、ECDSA r‖s 或 DER。
Completed done = EidPades.complete(prepared.state(), signature);
Files.write(Path.of("signed.pdf"), done.pdf());

// 4. 登记——RP-API 的 POST /pdf/signatures 请求体（不是 PDF，仅为元数据），请原样发送：
String body = done.registration(sessionId, orgRegNo).toJson();   // medium 由 sessionId 推断：有则为 PHONE，否则为 TOKEN
// 或显式指定： done.registration(Medium.TOKEN, null, null)
```

`registration(medium, sessionId, onBehalfOf)` 会在发往 CA 之前抛出 `REQUEST_INVALID`：`Medium.PHONE` 没有
`sessionId`、`Medium.TOKEN` 带有 `sessionId`、revIndex 1 没有 verify 页、没有 `fileName`，或在带 `claimedRole` 的
prepare 中 `onBehalfOf`（NTRMN-…）为空。若 `medium` 为 null，则由 `sessionId` 推断（CA 的配对：phone ⇔ sessionID）。

之前的签名只通过 `priorCmsSha256` 发送——若将 `priorCmsSha256` 和 `priorRevisionSha256` **两者**
都完整发送，CA 会返回 400。若之前的签名由 CA 组装（模式 A），CA 会返回 409 `PRIOR_MISMATCH`：
请用 `reg.withPriorByRevision(k)`（将前 k 个移到 `priorRevisionSha256`）重新发送。

`CompleteOptions.builder()`：`tsaUrl`（默认 `https://tsa.timeserver.mn/`）、`roots`（测试 PKI）、`transport`
（`EidPadesTransport`——proxy/sandbox；默认为 `HttpURLConnection`，每个请求总计 10 s 的 deadline，不跟随重定向，
≤ 4 MiB）。国家 CRL（`esign.gov.mn`）从 eID 的 https 镜像获取（WIRE.md §3）。

## 错误

所有错误均为 `EidPadesException`（unchecked）；请根据 `code()`（稳定，所有 SDK 相同）分支处理，
`getMessage()` 仅用于日志。`retryable()`——TSA/LTV 的临时性错误（用相同的 state + 签名再次调用 `complete`）。

| 代码 | 含义 |
|---|---|
| `PDF_INVALID` | PDF 无法解析；结构过深（嵌套 > 256）、ObjStm 循环、`/Extends` > 64、`/Size` > 2^21（PRECHECKS #2a/#2b） |
| `PDF_ENCRYPTED` | 已加密的 PDF |
| `PDF_LOCKED` | DocMDP P=1——禁止修改 |
| `PDF_TOO_LARGE` | 超过 9.75 MiB（输入）/ 10 MiB（输出） |
| `PDF_TOO_MANY_SIGNATURES` | 超过 16 个签名 |
| `PDF_PRIOR_SIGNATURE_INVALID` | 之前的签名已损坏 |
| `PDF_FOREIGN_SIGNATURE` | 之前的签名不是 eID 的 B-LT |
| `SIGNER_INVALID` | signerCert / 证书链有误 |
| `REQUEST_INVALID` | 选项有误（docId、lang、fileName、appearance、claimedRole、medium…） |
| `SIGNATURE_INVALID` | 签名与 DTBS / signerCert 不匹配 |
| `TSA_UNAVAILABLE` | TSA 无响应 / token 无效 |
| `LTV_UNAVAILABLE` | 无法完整获取 OCSP/CRL；若 `LtvUnavailable.certificateRevoked()` 为真，则链中某证书已吊销——不要重试 |
| `SELF_VALIDATION_FAILED` | 输出未通过自身校验 |
| `PLACEHOLDER_OVERFLOW` | 放不进 CMS placeholder |
| `STATE_INVALID` | `state` 已损坏（或其 PDF 的结构过深/过于复杂） |
| `INTERNAL` | SDK 内部错误 |

### 可见签名的位置

`SignatureAppearance` 的 `x/y` 是**请求的**位置。Prepare 会在不渲染的情况下读取目标页面（文字、表格线、图片、form
XObject、annotation 的 `/Rect`），若请求的矩形（+4 pt）与内容重叠，就会将其移到第一个空闲
位置（同一高度的镜像列 → 在请求的列中每次上移 12 pt → 在镜像列中上移）。
`prepared.placement()`（`page`、`x`、`y`、`width`、`height`——pt；`status`）：`REQUESTED` | `MOVED` | `OVERLAP`（没有空闲
区域，仍在请求的位置）| `UNSCANNED`（在限制内无法读取该页，仍在请求的位置）。建议将 `OVERLAP` / `UNSCANNED` 告知
用户——签名在任何情况下都有效。规则：Go 仓库的 `pades/PLACEMENT_SPEC.md`。

**让公民自行放置**（PLACEMENT_SPEC §6a/§6b）：`EidPades.suggestPlacement(pdf, appearance)` 在没有签名、证书和网络的情况下运行 prepare 的位置
算法，返回默认位置和页面尺寸（`pageWidth`、`pageHeight`、`pageCount`、
`pages()`）。若通过 `appearance.withExact(true)` 传入公民拖动后的位置，图章会被准确绘制在那里（绝不会
移动；压在内容上则为 `OVERLAP`，超出页面则为 `REQUEST_INVALID`）。屏幕（左上，`s` px/pt）↔ appearance：
`left = x·s`，`top = (pageHeight − y − height)·s`。

## “我的 QR”——公民的“我的信息”（`EidQr`）

公民在 eID 应用中展示“我的 QR”（`EIDMN-QR1:<token>`）→ RP 扫描后**直接**调用 RP-API 的 `POST /authentication/qr`
→ 公民用 PIN2 批准 → RP 获得公民的“我的信息”，形式为用公民的 QUALIFIED SIGN 密钥签名的
**PS256 JWS**（`typ` = `eidmn-myqr+jwt`，`x5c` = [公民证书, 颁发 CA]）。本库会验证该 JWS：

```java
EidQr.Parsed qr = EidQr.parse(scanned);              // 若为 QR_FORMAT_INVALID，则不要发送给 RP-API
// … 将 qr.qr() 发送到 POST /authentication/qr，并从 session 结果中取得 JWS（RP-API，直接 HTTPS）
EidQr.Result r = EidQr.verify(jws, new EidQr.Expect(rpUuid, sessionId, nonce));
for (Map.Entry<String, String> f : r.data()) show(f.getKey(), f.getValue());   // 按 payload 的顺序
// r.source(), r.photo() (JPEG | null), r.signer().etsi(), r.signedAt()、r.sha256()（= CA 审计中的 qrsha）、r.jws()
```

验证（与 Go / TS / .NET 相同，使用 CA 的 `myqr_vectors.json`）：JWS ≤ 512 KiB，3 段 → header 必须恰好是 `alg` PS256 / `typ` /
`x5c` 为 2 张证书 → 证书链（x5c[1] 仅作为中间证书候选，±60 s）+ leaf：非 CA，KeyUsage contentCommitment，
QcCompliance，颁发者的 SKI ∈ 允许集合（默认 04 `EidQr.CITIZEN_ISSUING_CA_SKI`），RSA ≥ 2048 → 吊销（默认为 AIA 中的
OCSP，hard-fail）→ RSASSA-PSS SHA-256（salt 32）→ `iss`、`sub`、`statement`、`aud`（不区分大小写）、`sid`、`nonce`、
0 < exp − iat ≤ 300、±60 s → `data` 限制。`EidQr.Trust(anchors, intermediates, allowedIssuerSkis, revocation,
revocationSoftFail)`——为 null 时使用内置的国家 root + 02–05、颁发者 04、OCSP。

代码（`EidQrException.code()`）：`QR_FORMAT_INVALID`、`QR_JWS_MALFORMED`、`QR_HEADER_INVALID`、`QR_CHAIN_INVALID`、
`QR_CERT_REVOKED`、`QR_REVOCATION_UNKNOWN`、`QR_SIGNATURE_INVALID`、`QR_CLAIMS_INVALID`、`QR_AUDIENCE_MISMATCH`、
`QR_SESSION_MISMATCH`、`QR_NONCE_MISMATCH`、`QR_NOT_YET_VALID`、`QR_EXPIRED`、`QR_DATA_INVALID`。RP-API 的 HTTP 错误
（`QR_TOKEN_INVALID`、`QR_PRESENTATION_GONE` ……）会出现在您的 HTTP 客户端中。

## 开发

- Profile 规则：Go 仓库的 `pades/PROFILE.md`、`PAGE_SPEC.md`、`PRECHECKS.md`、`WIRE.md`、`APPEARANCE_SPEC.md`、
  `PLACEMENT_SPEC.md`。
- Golden：`src/test/resources/golden` = Go 仓库的 `pades/testdata/golden`（+ `validate/` 输入），取自 `golden/SOURCE` 中的
  tag（`scripts/sync-pades-golden.sh <tag>`；CI 的 `golden-sync` job 用 `--check` 比对）。测试 PKI 的私钥
  已移除——公民的签名已写在 manifest 中。`myqr_vectors.json`——CA 的合约 vector（sha256 已固定）。
- 测试（`./gradlew build`，仅在 CI 中）：每个 golden 用例都执行 prepare → manifest 的签名 → complete（HTTP fixture
  回放，固定 nonce/时间）→ 将输出 PDF 的 sha256 与 Go 的比对；placement vectors（每个 box）、validate v4
 （吊销证据、结构检查）、错误代码、“我的 QR” vectors。
- 字体（`src/main/resources/.../fonts`）：Noto Sans 子集，SIL OFL 1.1——与 Go reference 的 `pades/assets/fonts` 字节相同。

## Release

1. `release/<版本>` 分支：将 `changelog.d/*` 合并到 `CHANGELOG.md` 的 `## <版本> — <日期>` 部分后
   删除 → PR → merge。
2. 在 main 上执行 `git tag <版本> && git push origin <版本>`（tag 不带 `v`——JitPack 的版本 = tag，与 Android SDK 相同）。
3. `.github/workflows/release.yml`：完整运行 CI（Linux + Windows），并将 jar/sources/javadoc 附加到 GitHub Release。
   JitPack 会自行根据 tag 构建（`jitpack.yml`）。

## 许可证

MIT——[LICENSE](LICENSE)。字体：SIL Open Font License 1.1（`src/main/resources/mn/eidmongolia/eid/pades/fonts/OFL.txt`）。
