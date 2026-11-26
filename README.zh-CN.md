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
- 线程安全，无全局状态。PAdES 仅在 `complete`（TSA、OCSP/CRL）以及 `EidQr.verify` 的默认 OCSP 中使用网络。
- **完整的 RP-API 客户端**（`mn.eidmongolia.eid`，自 0.2.0 起）：认证、签名、session、带 OCSP 吊销检查的响应验证器、
  PDF 签名登记、组织 / 个人 / e-Seal / 令牌 / 分享、“我的 QR”客户端以及“使用 eID 登录”按钮后端——范围与 Go 和
  TypeScript SDK 相同（见下文支持矩阵）。
- 验证已签名的 PDF（`EidPades.validatePdf`）——与 Go / TS 相同的报告（见下文）。


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
    implementation("com.github.gerege-systems:eid-mongolia-sdk-java:0.2.0")
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
  <version>0.2.0</version>
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
| `PDF_INVALID` | PDF 无法解析；结构过深（嵌套 > 256）、ObjStm 循环、`/Extends` > 64、`/Size` > 2^21、xref 节 > 128、xref 流 `/W` / `/Index` / 行数 > 2^21、对象流工作量 > 1 GiB（PRECHECKS #2a/#2b） |
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

## RP-API 客户端（`mn.eidmongolia.eid`）

完整的依赖方（relying-party）SDK——范围与线上行为同 Go 和 TypeScript SDK（跨 SDK 一致性语料 `rp-conformance/2`：
wire、validator、OCSP、ACSP、interactions；登录按钮后端为 `eidlogin/2`）。所有调用都是阻塞的（适合虚拟线程）；
`Thread.interrupt()` 会取消正在进行的调用（`EidException.Network#cancelled`）。

### 客户端、trust 与 mTLS

```java
TrustConfig trust = TrustConfig.builder()
    .trustAnchorsPem(Roots.NATIONAL_ROOT_CA_PEM)          // 内置国家根证书（01）；02–04 已内置
    .revocation(OcspRevocationChecker.create())           // checkRevocation 的 OCSP（不设置则关闭）
    .revocationMode(RevocationMode.HARD_FAIL)             // 设置 checker 后 validator 的默认值
    .build();
EidClient eid = EidClient.builder(new Credentials(rpUuid, "Internet bank", apiSecret))
    .trust(trust)
    .transport(JdkHttpTransport.create(sslContext))      // mTLS：客户端证书放在 SSLContext 中；默认 create()
    .language("en")                                      // Accept-Language
    .build();                                            // baseUrl 默认 https://rp.eidmongolia.mn
SessionTtl ttl = eid.auth().sessionTtl();                // discovery：auth / sign session 有效期
```

- `baseUrl`：仅 https（http 仅限 localhost / loopback），旧的 `ca.eidmongolia.mn` 主机会给出明确错误；Bearer API secret；
  每次调用有总截止时间（默认 15 秒，PDF 登记 80 秒）；JSON 响应 ≤ 4 MiB；不跟随重定向。
- 错误：`EidException`（unchecked）——`Authentication`（401）、`Forbidden`（403）、`Api` 及按代码划分的子类
  （`NoSigningCertificate`、`SealServiceDisabled` …）、`Network`、`ResponseTooLarge`、`SessionFailed`、`Validation`
  （`reason()` = 语料中的稳定键，如 `chain.untrusted`）、`Ocsp`、`DeviceLink`；均有 `code()`、`status()`、
  `retryAfter()`、`retryable()`。消息中不含公民身份号。不自动重试（同 Go / TS）。

### 认证：推送与 QR

```java
List<Interaction> ix = List.of(Interaction.displayTextAndPin("Log in to Internet bank"));

// 推送到公民手机（身份证号、公民号或 ETSI PNOMN-…）
NotificationSession push = eid.auth().notificationByEtsi("УБ12345678", ix, null);
show(push.vc());                                          // 公民核对的验证码

// 在您的页面上显示 QR（anonymous device link）：每秒生成新的 QR 链接
DeviceLinkSession qr = eid.auth().deviceLinkAnonymous(ix, null);
Thread ticker = new Thread(() -> {
    try {
        DeviceLink.tickQr(qr.linkInput(DeviceLinkType.QR, "eng").build(), Duration.ofSeconds(1), link -> render(link));
    } catch (InterruptedException e) { /* 已停止 */ }
});
ticker.start();

// Session：等待结果后验证（证书链 + ACSP_V2 签名 + 流程类型）
SessionResult res = eid.session().waitForResult(qr.sessionId(), WaitOptions.builder().expiresAt(qr.expiresAt()).build());
ticker.interrupt();
VerifiedIdentity id = eid.validator().validateAuth(res, qr.acsp(),
    ValidateAuthOptions.builder().expectedFlowType(FlowType.QR).build());
eid.validator().checkRevocation(id.certificate());       // OCSP（TrustConfig.revocation）
String etsi = id.subject().serialNumber();                // PNOMN-…
```

`session().poll(sessionId, serverPoll)` 是单次长轮询；`waitForResult` 循环直到 COMPLETE 或超时
（`maxWait` → `expiresAt` → discovery `sessionTtl` → 600 秒，+ 15 秒）。Web2App / App2App：在 `AuthOptions` 中传入
`callbackUrl`，并把回调中的 `userChallengeVerifier` 传给 `ValidateAuthOptions`（这些流程中为必填）。

### 验证器与吊销

`client.validator()` = `ResponseValidator`：`validateAuth`（ACSP_V2：流程类型中继检查、userChallengeVerifier、回调规则、
算法 / hash 降级检查、签名）、`validateSign`（RAW_DIGEST：prehashed RSASSA-PSS、PKCS#1 v1.5、ECDSA P-256）、
`validateCertificateChoice` → `Signer`。证书链由确定性的手写路径构建器构建（非 PKIX）：内置根证书、签发者 SKI 白名单、
时钟偏差、pathLen、KeyUsage / EKU，对 name constraints 与未知关键扩展 fail-closed，链签名仅限 SHA-2，RSA ≥ 2048，
subject 中 SERIALNUMBER 或 CN 多于一个时拒绝（`subject.duplicate_identity`）。

吊销（`OcspRevocationChecker`：OCSP `unknown` = 已吊销，thisUpdate 在 48 小时内，缓存 ≤ 5 分钟，每次请求 2 秒 / 总计
3 秒，CertID 与签发者绑定）：

| 位置 | 默认 | 没有 OCSP 应答时 |
|---|---|---|
| `validator().checkRevocation` | 在设置 `TrustConfig.revocation(...)` 之前**关闭** | `HARD_FAIL`（设置后的默认）→ `EidException.Validation`；`SOFT_FAIL` → 以 `UNCHECKED` 接受 |
| 登录按钮后端（`EidLogin`） | OCSP **开启**，**soft-fail** | 接受并记录日志，`identity.revocation() == UNCHECKED` |
| 我的 QR（`EidQr.verify`、`client.qr()`） | OCSP 开启，hard-fail | `QR_REVOCATION_UNKNOWN` |

登录后端默认为 **soft-fail**（OCSP 故障时不会把所有人挡在外面）。**高价值的依赖方（银行、公证，任何涉及资金或法律效力的
场景）应使用 hard-fail**：`EidLogin.builder(eid).revocationMode(RevocationMode.HARD_FAIL)`，并为 validator 设置
`TrustConfig.revocation(...)`。

### 签名

```java
// 先确定证书（client-side PAdES / CMS）：证书选择 → 签名人
NotificationSession cc = eid.sign().certificateChoiceByEtsi("УБ12345678", null);
SessionResult ccr = eid.session().waitForResult(cc.sessionId(), WaitOptions.builder().expiresAt(cc.expiresAt()).build());
Signer signer = eid.validator().validateCertificateChoice(ccr, cc.sessionId());

// 摘要（如 EidPades.prepare(...).dtbs()）——在手机上用 PIN2 签名
String dtbsB64 = Base64.getEncoder().encodeToString(prepared.dtbs());
NotificationSession s = eid.sign().digestForSigner(signer.ref(), dtbsB64, ix, null);
SessionResult sr = eid.session().waitForResult(s.sessionId(), WaitOptions.builder().expiresAt(s.expiresAt()).build());
VerifiedSignature sig = eid.validator().validateSign(sr, dtbsB64, HashAlgorithm.SHA_256);
```

另有 `digestByEtsi`、`digestByDocument`、`textByEtsi`、`deviceLinkByEtsi` / `deviceLinkByDocument` /
`deviceLinkForSigner`（QR / Web2App）、`certificateChoiceDeviceLink`；`SignOptions`（certificateLevel、hash / 签名算法、
`onBehalfOf`、callbackUrl、fileName）。

### PDF 签名登记

```java
Completed done = EidPades.complete(prepared.state(), Base64.getDecoder().decode(sig.signatureValueB64()));
PdfSignatureRegistered reg = eid.pdf().registerSignature(done.registration(s.sessionId(), null));
// reg.docId()、reg.revIndex()（1…16）、reg.verifyUrl()、reg.created()（false = 幂等重复）
```

`POST /pdf/signatures`；遇到 409 `PRIOR_MISMATCH` 时按 Go / TS 的方式重试先前签名的组合。无效输入（缺少 docID / cms、
revIndex 不在 1…16、手机签名缺少 sessionID …）会在发出任何请求之前抛出 `IllegalArgumentException`。

### 组织、个人、e-Seal、令牌、分享

- `organization()`：`getRepresentations(personEtsi)`、`sealGrants(personEtsi)`。
- `person()`（PKI_READ）：`certificates`、`devices`、`activity(etsi, ActivityQuery)`、`summary`、`children`。
- `seal()`：`certificate`、`requestCertificate`、`certificateRequest`、`waitForCertificate`、`requestGrant`、
  `grantStatus`、`waitForGrant`、`seal(orgEtsi, digest, hash)`——用 e-Seal 证书验证返回的 ECDSA 签名；
  `sealForDocument(orgEtsi, digest, docId, revIndex)`（带 QR 印章的预留）、`registerSealedPdf(orgEtsi, registration)`
  （见「为 PDF 加盖电子印章」）；`isSealCertificate`。
- `token()`：`issueCertificate`、`previewCertificate`、`certificateResult`、`certificateInfo`、`authChallenge`、
  `authVerify`（发送前用 validator 的证书链检查 r‖s 签名与证书），静态方法 `verifyTokenCertificates`、
  `tokenAuthDigest`、`tokenLimitOf`。
- `share(ShareRequest)`（以 multipart 邮件发送已签名文件；CA 不保存）与 `shareInfo()`。
- 路径参数（ETSI / session / request id）为空、`.` 或 `..` 时在发出任何请求之前即被拒绝。

### 我的 QR 客户端

```java
EidQr.Parsed p = eid.qr().parse(scanned);                           // QR_FORMAT_INVALID → 不要发送
QrSession qs = eid.qr().start(new QrStartRequest(p.qr()));            // POST /authentication/qr
EidQr.Result r = eid.qr().result(qs, WaitOptions.builder().maxWait(Duration.ofMinutes(2)).build());  // 手机上输入 PIN2
// r.data()、r.signer().etsi()、r.photo() …——已由 EidQr.verify 验证（见上文“我的 QR”）
```

`check(qs, serverPoll)` 是单次长轮询；`verify(jws, qs)` 验证您已持有的 JWS。`EidClient.Builder.qrTrust` / `qrIssuer`
可覆盖 trust 与签发者。

### 为 PDF 加盖电子印章（`EidPades.sealPdf`）

```java
// 默认：可见印章图案（无 QR / 链接），位于最后一个非 eID verify 页的右下角
Completed sealed = EidPades.sealPdf(eid.seal(), "NTRMN-1234567", pdf, SealOptions.builder().build());
Placement where = sealed.placement();   // null = 不可见
// 自定位置：.appearance(new SignatureAppearance(1, 36, 36, 220, 64, "en", true))；不加图案：.invisible(true)
```

机构印章图案（Go `SealPDF`，APPEARANCE_SPEC §6，golden v12）：自动位置最大 220 × 64 pt，距边 36 pt，若覆盖页面内容则移到
空闲位置（PLACEMENT_SPEC）；页面放不下或字体会使输出超过大小上限时，改为不可见印章（`placement()` = null）。显式
`appearance` 无效时为 `REQUEST_INVALID`。用 e-Seal 证书（KeyUsage 仅 nonRepudiation、无 EKU）调用带外观的 `prepare`
也会绘制印章图案。

**行为变更（相对 0.2.0，与 Go 一致）：**
- `sealPdf` 默认绘制可见图案——0.2.0 中 `invisible(false)` 为 `REQUEST_INVALID`。早于印章图案的验证器（旧版 CA / TS SDK）
  会把之前的签名报告为已修改——在它们更新之前请使用 `invisible(true)`（其输出与 0.2.0 逐字节相同）。
- 已签名文档的 `docId`（APPEARANCE_SPEC §6.6，golden v13）：verify 页；否则带 QR 的机构印章图案的 `/EIDVerify` 标记；
  否则 `PrepareOptions.docId`；与已找到的 docId 不一致则 `REQUEST_INVALID`（不可见签名亦然）。已签名文档不会生成随机
  docId（与之前相同）。仅在要求时（`SealOptions.qr`，见下）输出带 QR 的印章图案（§6.5）。

**带 QR 的印章图案与印章登记（CA V158，与 Go / TS 相同）：**

```java
Completed sealed = EidPades.sealPdf(eid.seal(), "NTRMN-1234567", pdf, SealOptions.builder()
    .qr(true)                       // 图案带指向 /verify/<docId>/<revIndex> 的 QR；盖章时预留该位置
    .fileName("Invoice.pdf")        // 可选，显示在 /verify（≤ 120 个字符）
    .build());
PdfSignatureRegistered reg = eid.seal().registerSealedPdf("NTRMN-1234567", sealed.sealRegistration()); // 7 天内
```

`qr(true)` 需要 `DocumentSealer`（`eid.seal()` 即是；普通 `Sealer` → `REQUEST_INVALID`），不能与 `invisible(true)` 同用，且仅在
实际绘制了带 QR 的图案时才通过 `sealForDocument` 预留 `(docId, revIndex)`。没有 verify 页 / 带 QR 印章的已签名文档需提供
`SealOptions.docId`。`Completed.sealRegistration()` 生成 `POST /seal/{orgEtsi}/registrations` 的请求体（无 QR 的印章亦可）；
`registerSealedPdf` 在发送前校验（`IllegalArgumentException`），201 → `created()` 为 true，相同请求体的幂等重放 200 → false，
`PRIOR_MISMATCH` 时与 `pdf().registerSignature` 相同地重试各种组合，CA 错误码见 `EidErrorCodes.SEAL_REGISTER`（类型化的
`SealNotFound`、`SealDocMismatch`、`DocIdReserved`）。不使用 `qr` 时输出与之前逐字节相同。

### 验证已签名的 PDF（`EidPades.validatePdf`）

```java
PdfReport r = EidPades.validatePdf(pdf, ValidatePdfOptions.DEFAULT);   // mn.eidmongolia.eid.pades.validate
r.indication();                       // "valid" | "invalid" | "indeterminate"
r.signatures().get(0).problems();     // ["revoked"]、["modified_after_signing"] …
String json = r.toJson();             // 与 CA 的 /v3/validate/pdf 相同的 JSON（与 Go / TS SDK 一致）
```

移植自 Go `pades.ValidatePDF` / TS `validatePdf`：ByteRange / messageDigest、CMS 签名（RSA PKCS#1 / ECDSA）、
signing-certificate-v2、到国家根 CA 的证书链（fail-closed：带 nameConstraints 或未知关键扩展的证书不进入链；RSA ≥ 2048）、
KU/EKU、RFC 3161 时间戳、签名之后的修订（shadow / 追加的修改 → `modified_after_signing`；可见印章按 APPEARANCE_SPEC §5）、
吊销（DSS 中的 OCSP/CRL；`offline(false)` 时还有 AIA OCSP / CDP CRL）、LTV、`PAdES-BASELINE-B/T/LT`、`certificate_level`。
选项：`roots`、`intermediates`、`issuers`、`time`、`offline`、`transport`（`EidPadesTransport`）。文档不会离开进程——网络上
只有证书序列号（OCSP）。错误：`ValidatePdfException.code()` = `PDF_TOO_LARGE` / `PDF_INVALID` / `PDF_ENCRYPTED` /
`PDF_NO_SIGNATURE` / `PDF_TOO_MANY_SIGNATURES` / `REQUEST_INVALID`。对恶意 PDF 有上限（与 Go / TS 相同，语料库 v14）：
10 MiB、16 个签名、嵌套 ≤ 256；xref 节 ≤ 128（`trailer` 字典 + `/Type /XRef` 字典），xref 流每个 `/W` 项 0…8 且行宽 > 0，
`/Index` start + count ≤ 2^21，所有 xref 流的行数合计 ≤ 2^21，xref / 对象流只允许一个过滤器，解压后的 xref + 对象流合计
≤ 32 MiB，对象流成员查找工作量（头部对数 × 解压长度）合计 ≤ 1 GiB——超出任一项即 `PDF_INVALID`；每个 CMS 或时间戳令牌
≤ 32 个证书、RSA ≤ 8192 位、e ≤ 2^32−1、证书 / TSTInfo 序列号 ≤ 160 位（否则 `malformed_signature`）；DSS 解码合计
≤ 8 MiB（同一数组中重复引用的流只读一次）。**集成方可见的变化：** 超过 128 次增量更新或对象流成员极多的文档 →
`PDF_INVALID`；后续签名完整性校验失败时，之前的签名为 `modified_after_signing`（后续可见印章的 `/Name` 不与其证书名称
比较——语料库 v15；`signer_name` 取自证书，`claimed_name` 取自 `/Name`）；SignerInfo 使用 MD2/MD5/SHA-1 签名算法 → `weak_algorithm`。

### “使用 eID 登录”按钮后端（`mn.eidmongolia.eid.login`）

浏览器 `<eid-login-button>`（TS SDK）的后端——JSON、cookie 与状态码同 Go `eidlogin` / TS `createEidLogin`（通过 `eidlogin/2` 一致性语料的全部 34 个场景）。`EidLogin.handle(EidLoginRequest)` 与框架无关；JDK 服务器用 `EidLoginHttpHandler`，Servlet / Spring 见下例。推送不会泄露号码是否已注册（诱饵会话、1 秒下限）；cookie 为 HttpOnly + Secure + SameSite=Lax；状态保存在服务器（`EidLoginStore`，默认内存）；默认启用 OCSP 吊销检查（soft-fail——见上文）。

```java
EidLogin login = EidLogin.builder(eid)                      // eid = EidClient（trust：含国家根证书的 TrustConfig）
    .callbackUrl("https://bank.mn/auth/eid/callback")      // Web2App；路径必须为 /auth/eid/callback
    .failureRedirect("/login")
    .onSuccess((id, req) -> {                              // id.etsi() = PNOMN-…；创建新的会话
        String sid = sessions.create(id.etsi());
        return new EidLoginSuccess("/home", null, Map.of("Set-Cookie", List.of("sid=" + sid + "; Path=/; HttpOnly; Secure; SameSite=Lax")));
    })
    .build();

// JDK com.sun.net.httpserver
HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
server.createContext("/auth/eid/", new EidLoginHttpHandler(login, EidLoginHttpHandler.ClientIp.direct()));
server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());   // Java 21+——必须设置（见下文）
// server.setExecutor(Executors.newFixedThreadPool(64));           // Java 17：有界线程池
server.start();
// JVM 参数（秒）：-Dsun.net.httpserver.maxReqTime=10 -Dsun.net.httpserver.maxRspTime=30——或使用带超时的反向代理

// Servlet（jakarta.servlet）——映射到 /auth/eid/*
protected void service(HttpServletRequest rq, HttpServletResponse rs) throws IOException {
    Map<String, List<String>> h = new HashMap<>();
    for (String n : Collections.list(rq.getHeaderNames())) h.put(n, Collections.list(rq.getHeaders(n)));
    String url = rq.getRequestURI() + (rq.getQueryString() == null ? "" : "?" + rq.getQueryString());
    byte[] body = rq.getInputStream().readNBytes(4097);          // 最多 4 KiB + 1——更大的由 EidLogin 拒绝
    EidLoginResponse r = login.handle(new EidLoginRequest(rq.getMethod(), url, h, body, rq.getRemoteAddr()));
    rs.setStatus(r.status());
    r.headers().forEach((k, vs) -> vs.forEach(v -> rs.addHeader(k, v)));
    rs.getOutputStream().write(r.body().getBytes(StandardCharsets.UTF_8));
}

// Spring MVC——自行有界地读取请求体（不要使用无界的 @RequestBody byte[]）
@RequestMapping("/auth/eid/{op}")
ResponseEntity<String> eid(HttpServletRequest rq) throws IOException {
    Map<String, List<String>> h = new HashMap<>();
    for (String n : Collections.list(rq.getHeaderNames())) h.put(n, Collections.list(rq.getHeaders(n)));
    String url = rq.getRequestURI() + (rq.getQueryString() == null ? "" : "?" + rq.getQueryString());
    byte[] body = rq.getInputStream().readNBytes(4097);
    EidLoginResponse r = login.handle(new EidLoginRequest(rq.getMethod(), url, h, body, rq.getRemoteAddr()));
    HttpHeaders out = new HttpHeaders();
    r.headers().forEach(out::addAll);
    return new ResponseEntity<>(r.body(), out, HttpStatus.valueOf(r.status()));
}
```

**线程。** `handle` 是阻塞的：status 调用最多占用线程 `poll` 时长（默认 1 秒；每个登录同一时间只有一个——同一登录的并发
status 调用立即返回 `PENDING`），push 启动至少占用 1 秒下限。请使用虚拟线程（Java 21+）或按并发登录数配置的有界线程池。
未调用 `setExecutor` 的 JDK `HttpServer` 会在唯一的 dispatcher 线程上处理所有请求——一个缓慢或循环的客户端就会阻塞所有
登录（handler 会记录一次警告）。JDK 服务器默认没有读取截止时间：请设置 `sun.net.httpserver.maxReqTime` / `maxRspTime`
（秒），或在前面放置带请求超时的反向代理。

**`start:<ip>` 限流的客户端 IP——以下两种只能选其一。**

*A——客户端直接连接（无代理）：* 不要在 builder 上调用 `.clientIp(...)`。由适配器传入 socket 地址：
`EidLoginHttpHandler.ClientIp.direct()`，Servlet / Spring 用 `rq.getRemoteAddr()`（如上）。

*B——位于 N 个受信任反向代理之后（仅 nginx = 1）：*

```java
EidLogin login = EidLogin.builder(eid)
    .clientIp(EidLogin.forwardedClientIp(1))               // X-Forwarded-For，从右数第 1 个值
    // … 其余同上
    .build();
// JDK：ClientIp.trustedProxies(1) 在适配器中实现同样效果（此时不要设置 builder 的 clientIp）
```

> **警告：** builder 上的 `.clientIp(...)` 会覆盖适配器传入的地址。若把 B 复制到没有代理的部署中，每个客户端都可以通过
> `X-Forwarded-For` 自选限流键。无法推导出的地址（代理链比配置的短）计入一个共享的 `start:unknown` 桶；IPv6 客户端按其
> /64 前缀计数。完全没有 IP 来源时按 IP 的限流关闭，并记录一次警告。

按号码的 push 限流（每个号码每分钟 3 次）的键为 `push:<pushKey>`——号码的审计 HMAC（`auditKey`；共享限流器的各实例请设置相同的
密钥），而不是号码本身：自定义 `rateLimit` 钩子或 Redis 中不会保存身份号（0.2.0 传入 `push:<id>`）。任何知道公民身份号的人
仍可耗尽该窗口，使该公民的 **push** 登录最多延迟一分钟——这是按号码推送的固有特性；QR 与 Web2App 不受影响。

登录 cookie 的默认名称为 `__Host-eid_login`（Secure、无 Domain、Path 为 `/`——浏览器不会接受来自兄弟子域或其他路径的同名
cookie）；使用 `insecureCookie`、`cookieDomain` 或其他 `cookiePath` 时默认仍为 `eid_login`，`cookieName(...)` 按原样使用。
请求中登录 cookie 出现不止一次时视为没有 cookie（status `EXPIRED`，callback `eid_error=expired`）。从 0.2.0 升级时，进行中的
登录会重新开始一次。

### 支持矩阵（与 Go / TypeScript SDK 对比）

| 功能 | Java 0.2.0 |
|---|---|
| 客户端、mTLS、错误、每天与线上 discovery 对照的路由表 | ✓ |
| 认证推送 / device link、QR ticker、ACSP_V2、interactions | ✓ |
| Session poll / waitForResult | ✓ |
| 签名（推送、device link、linked、文本）、证书选择 | ✓ |
| 验证器（认证、签名、证书选择）、根证书、OCSP 检查器、subject | ✓ |
| PDF 签名登记（`POST /pdf/signatures`） | ✓ |
| 组织、个人（PKI_READ）、e-Seal（证书、授权、摘要盖章）、令牌、分享 | ✓ |
| 我的 QR parse / verify / start / result / check | ✓ |
| 登录按钮后端（JDK 适配器；Servlet / Spring 示例） | ✓ |
| PAdES prepare / complete / suggestPlacement / 登记请求体 | ✓ |
| `sealPdf`（可见印章图案——默认，不可见） | ✓（golden v12） |
| 带 QR 的印章图案（`SealOptions.qr`）、已签名文档的 docId 规则 | ✓ golden v13 |
| ValidatePDF（验证已签名 PDF） | ✓ |
| 印章登记（`POST /seal/{orgEtsi}/registrations`、`sealForDocument`） | ✓ |

### 从 0.1.x 迁移

- 坐标、jar 的 `Automatic-Module-Name`（`mn.eidmongolia.eid.pades`——为兼容而保持不变，尽管 jar 现在还包含
  `mn.eidmongolia.eid`、`.login` 与 `.internal`）以及 `mn.eidmongolia.eid.pades` 的公共 API 均未改变：0.2.0 只做新增
  （`EidPades.sealPdf`、`Sealer`、`SealOptions`、`EidQrException.TOKEN_INVALID` / `PENDING` / `PRESENTATION_GONE` 以及带
  cause 的构造函数）。基于 0.1.1 编写的代码无需修改即可编译和链接（新增类型的常见注意事项：新的 `Sealer` / `SealOptions`
  名称在两个通配符 import 下可能与其他库的同名类型冲突）。
- `mn.eidmongolia.eid.internal` 仅为 SDK 自身的包而公开——不是 API，任何版本都可能改变。
- 行为变化（更严格，安全相关）：我的 QR 将 OCSP `unknown` 视为已吊销（`QR_CERT_REVOKED`，此前为
  `QR_REVOCATION_UNKNOWN`），并接受最多 48 小时前的 OCSP 应答（此前为 24 小时）；证书必须为严格 DER（见
  [CHANGELOG.md](CHANGELOG.md) 中 0.2.0 的安全说明）；拒绝 SHA-1 链签名与小于 2048 位的 RSA 密钥；OCSP CertID 必须与
  签发者一致；subject 中 SERIALNUMBER / CN 重复的证书会被拒绝。
- 如果您此前自行通过 HTTPS/JSON 调用 RP-API，可以逐步迁移到 `EidClient`——线上格式相同。

## 开发

- Profile 规则：Go 仓库的 `pades/PROFILE.md`、`PAGE_SPEC.md`、`PRECHECKS.md`、`WIRE.md`、`APPEARANCE_SPEC.md`、
  `PLACEMENT_SPEC.md`。
- Golden：`src/test/resources/golden` = Go 仓库的 `pades/testdata/golden`（+ `validate/` 输入），取自 `golden/SOURCE` 中的
  tag 或 commit（当前 golden v13 = commit `499aa5c`，无 tag；`scripts/sync-pades-golden.sh <tag|sha>`；CI 的 `golden-sync`
  job 用 `--check` 比对）。测试 PKI 的私钥
  已移除——公民的签名已写在 manifest 中。`myqr_vectors.json`——CA 的合约 vector（sha256 已固定）。
- ValidatePDF 语料库：`src/test/resources/pades-validate` = Go 仓库的 `pades/testdata/validate`（+ 其引用的 `golden/output|input`），
  取自 `pades-validate/SOURCE` 中的 commit（`scripts/sync-pades-validate.sh <commit>`；CI 的 `validate-sync` job 用 `--check` 比对；测试校验 `SHA256SUMS`）。
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
