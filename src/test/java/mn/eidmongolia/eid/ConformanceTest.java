package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.function.BiFunction;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.Test;

/**
 * The cross-SDK RP conformance corpus ({@code rp-conformance/1}) — src/test/resources/conformance is an UNEDITED copy
 * of the Go reference's testdata/conformance at the commit in conformance/SOURCE (scripts/sync-conformance.sh; CI
 * {@code conformance-sync}), README.md there is the spec. Port of Go conformance_test.go (TestConformanceManifest,
 * TestConformanceRPValidate, TestConformanceWire, TestConformanceInteractions, TestConformanceACSP, TestConformanceOCSP).
 * eidlogin/scenarios.json belongs to the login backend package and is only hash-checked here.
 */
public class ConformanceTest {
    static final String DIR = "conformance/";

    static byte[] bytes(String rel) {
        return TestRes.resource(DIR + rel);
    }

    static Json.Obj json(String rel) {
        return (Json.Obj) Json.parse(bytes(rel));
    }

    static String pemText(String rel) {
        return new String(bytes(rel), StandardCharsets.US_ASCII);
    }

    static X509Certificate cert(byte[] derOrPem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(derOrPem));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String sha256(byte[] b) {
        return TestRes.hex(EidCrypto.digest("SHA-256", b));
    }

    private static void runAll(String what, List<Object> cases, java.util.function.Consumer<Json.Obj> run) {
        List<String> failures = new ArrayList<>();
        for (Object o : cases) {
            Json.Obj c = (Json.Obj) o;
            try {
                run.accept(c);
            } catch (AssertionError | RuntimeException e) {
                failures.add(c.optString("name") + ": " + e);
            }
        }
        if (!failures.isEmpty()) fail(what + ": " + failures.size() + "/" + cases.size() + " failed\n" + String.join("\n", failures));
    }

    // ── manifest ──

    @Test
    public void manifest() throws IOException, URISyntaxException {
        Json.Obj m = json("manifest.json");
        assertEquals("rp-conformance/1", m.optString("version"));
        Json.Obj files = m.optObj("files");
        assertTrue("files " + files.keySet().size(), files.keySet().size() >= 40);
        for (String rel : files.keySet()) assertEquals(rel + " sha256", files.optString(rel), sha256(bytes(rel)));
        // Nothing else vendored: no generator keys, no stray files (SOURCE = the pinned Go commit).
        URL root = ConformanceTest.class.getResource("/" + DIR + "manifest.json");
        assertNotNull(root);
        Path dir = Paths.get(root.toURI()).getParent();
        TreeSet<String> onDisk;
        try (Stream<Path> s = Files.walk(dir)) {
            onDisk = s.filter(Files::isRegularFile).map(p -> dir.relativize(p).toString().replace('\\', '/'))
                .collect(Collectors.toCollection(TreeSet::new));
        }
        TreeSet<String> want = new TreeSet<>(files.keySet());
        want.add("manifest.json");
        want.add("SOURCE");
        assertEquals(want, onDisk);
        assertTrue(new String(bytes("SOURCE"), StandardCharsets.US_ASCII).trim().matches("[0-9a-f]{40}|rp-conformance-v[0-9]+"));
        // Our own copies of the frozen CA files are the ones the corpus pins.
        assertEquals(m.optObj("devicelinkGolden").optString("sha256"), sha256(TestRes.resource("devicelink_golden.json")));
        assertEquals(m.optObj("myqrVectors").optString("sha256"), sha256(TestRes.resource("myqr_vectors.json")));
        assertEquals(DeviceLinkGoldenTest.DEVICELINK_GOLDEN_SHA256, m.optObj("devicelinkGolden").optString("sha256"));
    }

    // ── rp-validate ──

    private static List<String> strings(List<Object> a) {
        List<String> out = new ArrayList<>();
        if (a != null) for (Object o : a) out.add((String) o);
        return out;
    }

    private static List<String> pems(List<Object> paths) {
        List<String> out = new ArrayList<>();
        for (String p : strings(paths)) out.add(pemText(p));
        return out;
    }

    static AcspContext acsp(Json.Obj a) {
        if (a == null) return null;
        List<FlowType> flows = new ArrayList<>();
        for (String f : strings(a.optArr("flowTypes"))) flows.add(FlowType.fromWire(f));
        return new AcspContext(a.optString("rpChallenge"), a.optString("relyingPartyName"), a.optString("brokeredRpName"),
            a.optString("interactions"), a.optString("initialCallbackUrl"), flows, SignatureAlgorithm.fromWire(a.optString("signatureAlgorithm")),
            HashAlgorithm.fromWire(a.optString("hashAlgorithm")));
    }

    static ResponseValidator validator(Json.Obj tr, Instant now) {
        String level = tr.optString("requiredLevel");
        TrustConfig t = TrustConfig.builder()
            .trustAnchorsPem(pems(tr.optArr("anchors")))
            .intermediatesPem(pems(tr.optArr("intermediates")))
            .allowedIssuerSkis(strings(tr.optArr("allowedIssuerSkis")))
            .requiredLevel(level.isEmpty() ? null : CertificateLevel.valueOf(level))
            .clockSkew(Duration.ofSeconds(tr.optLong("clockSkewSeconds", 0)))
            .build();
        return new ResponseValidator(t, Clock.fixed(now, ZoneOffset.UTC));
    }

    @Test
    public void rpValidate() {
        Json.Obj f = json("rp-validate/cases.json");
        assertEquals("rp-validate/1", f.optString("version"));
        Json.Obj trusts = f.optObj("trust");
        List<Object> cases = f.optArr("cases");
        assertEquals("cases", 77, cases.size());
        runAll("rp-validate", cases, c -> rpValidateCase(c, trusts));
    }

    private static void rpValidateCase(Json.Obj c, Json.Obj trusts) {
        Json.Obj tr = trusts.optObj(c.optString("trust"));
        assertNotNull("trust " + c.optString("trust"), tr);
        ResponseValidator v = validator(tr, Instant.parse(c.optString("now")));
        SessionResult r = SessionService.parseSessionResult(FakeRp.text(c.get("session")));
        Json.Obj o = c.optObj("options") == null ? new Json.Obj() : c.optObj("options");
        Json.Obj exp = c.optObj("expect");
        X509Certificate cert = null;
        String doc = null;
        CertificateLevel level = null;
        String alg = "";
        Subject subject = null;
        EidException err = null;
        try {
            switch (c.optString("kind")) {
                case "auth": {
                    VerifiedIdentity id = v.validateAuth(r, acsp(c.optObj("acsp")), ValidateAuthOptions.builder()
                        .expectedFlowType(FlowType.fromWire(o.optString("expectedFlowType")))
                        .userChallengeVerifier(o.optStringOrNull("userChallengeVerifier")).build());
                    cert = id.certificate();
                    subject = id.subject();
                    doc = id.documentNumber();
                    level = id.certificateLevel();
                    assertEquals(cert.getSubjectX500Principal().getName(), id.subjectDn());
                    break;
                }
                case "sign": {
                    ValidateSignOptions.Builder sb = ValidateSignOptions.builder()
                        .expectedFlowType(FlowType.fromWire(o.optString("expectedFlowType")))
                        .expectedAlgorithm(SignatureAlgorithm.fromWire(o.optString("expectedAlgorithm")));
                    if (!o.optString("expectedCertificate").isEmpty()) {
                        sb.expectedCertificate(cert(Base64.getDecoder().decode(o.optString("expectedCertificate"))));
                    }
                    String h = c.optString("hashAlgorithm");
                    HashAlgorithm hash = HashAlgorithm.fromWire(h);
                    assertTrue("hash " + h, h.isEmpty() || hash != null);
                    VerifiedSignature s = v.validateSign(r, c.optString("digest"), hash, sb.build());
                    cert = s.certificate();
                    subject = s.subject();
                    doc = s.documentNumber();
                    level = s.certificateLevel();
                    alg = s.signatureAlgorithm();
                    assertEquals(r.signatureValueB64(), s.signatureValueB64());
                    break;
                }
                case "certificateChoice": {
                    Signer s = v.validateCertificateChoice(r, c.optString("certChoiceSessionId"));
                    cert = s.certificate();
                    subject = s.subject();
                    doc = s.documentNumber();
                    level = s.certificateLevel();
                    assertEquals(c.optString("certChoiceSessionId"), s.certChoiceSessionId());
                    assertEquals(Base64.getEncoder().encodeToString(cert.getEncoded()), s.certificateDerB64());
                    assertEquals(new SignerRef(doc, c.optString("certChoiceSessionId")), s.ref());
                    break;
                }
                default:
                    fail("kind " + c.optString("kind"));
            }
        } catch (EidException e) {
            err = e;
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
        Json.Obj ee = exp.optObj("error");
        if (ee != null) {
            assertNotNull("expected error " + FakeRp.text(ee) + ", got success", err);
            switch (ee.optString("class")) {
                case "ValidationError":
                    if (!(err instanceof EidException.Validation)) throw new AssertionError("ValidationError expected", err);
                    assertEquals(err.getMessage(), ee.optString("reason"), ((EidException.Validation) err).reason());
                    break;
                case "SessionFailedError":
                    if (!(err instanceof EidException.SessionFailed)) throw new AssertionError("SessionFailedError expected", err);
                    assertEquals(ee.optString("endResult"), ((EidException.SessionFailed) err).endResult());
                    break;
                default:
                    fail("class " + ee.optString("class"));
            }
            return;
        }
        if (err != null) throw new AssertionError("success expected", err);
        Json.Obj ok = exp.optObj("ok");
        assertEquals(ok.optString("documentNumber"), doc);
        assertEquals(ok.optString("certificateLevel"), level.name());
        try {
            assertEquals(ok.optString("certificateSha256"), sha256(cert.getEncoded()));
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
        assertEquals(ok.optString("signatureAlgorithm"), alg);
        // The identity the validator RETURNED (not a re-parse of the certificate).
        Subject s = subject;
        assertEquals(Subject.parse(cert), s);
        Json.Obj ws = ok.optObj("subject");
        Map<String, String> got = new LinkedHashMap<>();
        got.put("serialNumber", s.serialNumber());
        got.put("givenName", s.givenName());
        got.put("surname", s.surname());
        got.put("country", s.country());
        got.put("commonName", s.commonName());
        Map<String, String> want = new LinkedHashMap<>();
        for (String k : got.keySet()) want.put(k, ws.optString(k));
        assertEquals(new TreeSet<>(want.keySet()), new TreeSet<>(ws.keySet()));
        assertEquals(want, got);
    }

    // ── wire ──

    private static Object pointerGet(Object v, String ptr) {
        for (String p : ptr.substring(1).split("/", -1)) {
            if (!(v instanceof Json.Obj)) return null;
            v = ((Json.Obj) v).get(p);
        }
        return v;
    }

    private static void pointerSet(Object v, String ptr, Object val) {
        String[] parts = ptr.substring(1).split("/", -1);
        Json.Obj o = (Json.Obj) v;
        for (int i = 0; i < parts.length - 1; i++) o = (Json.Obj) o.get(parts[i]);
        String last = parts[parts.length - 1];
        o.values.set(o.keys.lastIndexOf(last), val);
    }

    /** Go confResolve: "$request:&lt;pointer&gt;" → that value of the request body actually sent. */
    private static Object resolve(Object v, Object body) {
        if (v instanceof Json.Obj) {
            Json.Obj o = (Json.Obj) v;
            for (int i = 0; i < o.values.size(); i++) o.values.set(i, resolve(o.values.get(i), body));
        } else if (v instanceof List) {
            @SuppressWarnings("unchecked")
            List<Object> l = (List<Object>) v;
            for (int i = 0; i < l.size(); i++) l.set(i, resolve(l.get(i), body));
        } else if (v instanceof String && ((String) v).startsWith("$request:")) {
            Object x = pointerGet(body, ((String) v).substring("$request:".length()));
            return x == null ? Json.NULL : x;
        }
        return v;
    }

    private static Object orNull(Object v) {
        return v == null ? Json.NULL : v;
    }

    private static Object nullIfEmpty(String s) {
        return s == null || s.isEmpty() ? Json.NULL : s;
    }

    private static Map<String, Object> acspJson(AcspContext a) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("relyingPartyName", a.relyingPartyName());
        m.put("brokeredRpName", a.brokeredRpName());
        m.put("interactions", a.interactions());
        m.put("initialCallbackUrl", a.initialCallbackUrl());
        List<String> f = new ArrayList<>();
        for (FlowType t : a.flowTypes()) f.add(t.wireName());
        m.put("flowTypes", f);
        m.put("signatureAlgorithm", a.signatureAlgorithm().wireName());
        m.put("hashAlgorithm", a.hashAlgorithm().wireName());
        m.put("rpChallenge", a.rpChallenge());
        return m;
    }

    private static Map<String, Object> signJson(SignContext s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("digest", s.digest());
        m.put("hashAlgorithm", s.hashAlgorithm().wireName());
        m.put("signatureAlgorithm", s.signatureAlgorithm().wireName());
        m.put("relyingPartyName", s.relyingPartyName());
        m.put("interactions", s.interactions());
        m.put("initialCallbackUrl", s.initialCallbackUrl());
        return m;
    }

    /** Go confSessionJSON — the language-neutral parsed session (README §wire «parsed session»). */
    static Map<String, Object> sessionJson(SessionResult r) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("state", r.state());
        m.put("endResult", nullIfEmpty(r.endResult()));
        m.put("documentNumber", nullIfEmpty(r.documentNumber()));
        m.put("certificateDerB64", nullIfEmpty(r.certificateDerB64()));
        m.put("certificateLevel", nullIfEmpty(r.certificateLevel()));
        m.put("signatureValueB64", nullIfEmpty(r.signatureValueB64()));
        m.put("signatureAlgorithm", nullIfEmpty(r.signatureAlgorithm()));
        m.put("signatureProtocol", nullIfEmpty(r.signatureProtocol()));
        m.put("serverRandom", nullIfEmpty(r.serverRandom()));
        m.put("userChallenge", nullIfEmpty(r.userChallenge()));
        m.put("flowType", nullIfEmpty(r.flowType()));
        m.put("interactionTypeUsed", nullIfEmpty(r.interactionTypeUsed()));
        m.put("initialCallbackUrl", orNull(r.initialCallbackUrl()));
        SignatureAlgorithmParameters p = r.signatureAlgorithmParameters();
        Object sp = Json.NULL;
        if (p != null) {
            Map<String, Object> pm = new LinkedHashMap<>();
            pm.put("hashAlgorithm", p.hashAlgorithm());
            if (p.saltLength() != null) pm.put("saltLength", p.saltLength());
            sp = pm;
        }
        m.put("signatureAlgorithmParameters", sp);
        OrgResult o = r.onBehalfOf();
        Object om = Json.NULL;
        if (o != null) {
            Map<String, Object> x = new LinkedHashMap<>();
            x.put("orgEtsi", o.orgEtsi());
            x.put("orgName", nullIfEmpty(o.orgName()));
            x.put("role", nullIfEmpty(o.role()));
            x.put("rightType", nullIfEmpty(o.rightType()));
            if (!o.roleLabel().isEmpty()) x.put("roleLabel", o.roleLabel());
            if (!o.rightTypeLabel().isEmpty()) x.put("rightTypeLabel", o.rightTypeLabel());
            om = x;
        }
        m.put("onBehalfOf", om);
        Person pe = r.person();
        Object pm = Json.NULL;
        if (pe != null) {
            Map<String, Object> x = new LinkedHashMap<>();
            put(x, "firstName", pe.firstName());
            put(x, "lastName", pe.lastName());
            put(x, "familyName", pe.familyName());
            put(x, "firstNameEn", pe.firstNameEn());
            put(x, "lastNameEn", pe.lastNameEn());
            put(x, "civilId", pe.civilId());
            put(x, "regNo", pe.regNo());
            put(x, "birthDate", pe.birthDate());
            put(x, "gender", pe.gender());
            if (pe.geId() != 0) x.put("geID", pe.geId());
            put(x, "nationality", pe.nationality());
            pm = x;
        }
        m.put("person", pm);
        TokenCertSessionBlock t = r.tokenCertificate();
        Object tm = Json.NULL;
        if (t != null) {
            Map<String, Object> x = new LinkedHashMap<>();
            put(x, "status", t.status());
            put(x, "errorCode", t.errorCode());
            put(x, "authSerialHex", t.authSerialHex());
            put(x, "signSerialHex", t.signSerialHex());
            tm = x;
        }
        m.put("tokenCertificate", tm);
        return m;
    }

    private static void put(Map<String, Object> m, String k, String v) {
        if (v != null && !v.isEmpty()) m.put(k, v);
    }

    /** Go confWireExpect. */
    private static Map<String, Object> wireExpect(Object res, boolean hasExp) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (res instanceof NotificationSession) {
            NotificationSession r = (NotificationSession) res;
            m.put("type", "notification");
            m.put("sessionId", r.sessionId());
            m.put("vc", r.vc());
            m.put("rpChallenge", r.rpChallenge());
            m.put("acsp", r.acsp() == null ? Json.NULL : acspJson(r.acsp()));
            m.put("sign", r.sign() == null ? Json.NULL : signJson(r.sign()));
            if (hasExp) m.put("expiresAt", r.expiresAt() == null ? Json.NULL : r.expiresAt().toString());
        } else if (res instanceof DeviceLinkSession) {
            DeviceLinkSession r = (DeviceLinkSession) res;
            m.put("type", "deviceLink");
            m.put("sessionId", r.sessionId());
            m.put("vc", r.vc());
            m.put("sessionToken", r.sessionToken());
            m.put("sessionSecret", r.sessionSecret());
            m.put("deviceLinkBase", r.deviceLinkBase());
            m.put("sessionType", r.sessionType().wireName());
            m.put("rpChallenge", r.rpChallenge());
            m.put("acsp", r.acsp() == null ? Json.NULL : acspJson(r.acsp()));
            m.put("sign", r.sign() == null ? Json.NULL : signJson(r.sign()));
            if (hasExp) m.put("expiresAt", r.expiresAt() == null ? Json.NULL : r.expiresAt().toString());
            if (r.sessionType() == DeviceLinkSessionType.CERT) {
                m.put("relyingPartyName", r.relyingPartyName());
                m.put("callbackUrl", r.callbackUrl());
            }
        } else if (res instanceof SessionResult) {
            m.put("type", "session");
            m.put("session", sessionJson((SessionResult) res));
        } else {
            fail("result " + res);
        }
        return m;
    }

    /** Go confErrJSON. */
    private static Map<String, Object> errJson(EidException e) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (e instanceof EidException.Authentication) {
            m.put("class", "AuthenticationError");
        } else if (e instanceof EidException.Forbidden) {
            m.put("class", "ForbiddenError");
        } else if (e instanceof EidException.Api) {
            m.put("class", "ApiError");
        } else {
            throw new AssertionError("unexpected error", e);
        }
        m.put("status", e.status());
        m.put("code", e.code());
        if (e instanceof EidException.Api && e.retryAfter().compareTo(Duration.ZERO) > 0) m.put("retryAfterSeconds", e.retryAfter().getSeconds());
        return m;
    }

    @Test
    public void wire() {
        Json.Obj f = json("wire/cases.json");
        assertEquals("wire/1", f.optString("version"));
        Json.Obj cl = f.optObj("client");
        List<Object> cases = f.optArr("cases");
        assertEquals("cases", 26, cases.size());
        runAll("wire", cases, c -> wireCase(c, cl));
    }

    private static void wireCase(Json.Obj c, Json.Obj cl) {
        Json.Obj call = c.optObj("call");
        Json.Obj req = c.optObj("request");
        Json.Obj res = c.optObj("response");
        List<EidHttpRequest> seen = new ArrayList<>();
        EidTransport t = r -> {
            seen.add(r);
            Map<String, List<String>> h = new LinkedHashMap<>();
            h.put("Content-Type", List.of("application/json"));
            Json.Obj rh = res.optObj("headers");
            if (rh != null) for (String k : rh.keySet()) h.put(k, List.of(rh.optString(k)));
            return new EidHttpResponse((int) res.optLong("status", 0), h, EidCrypto.utf8(FakeRp.text(res.get("body"))));
        };
        EidClient client = EidClient.builder(new Credentials(cl.optString("rpUUID"), cl.optString("rpName"), cl.optString("apiSecret")))
            .baseUrl(cl.optString("baseUrl")).transport(t)
            .defaultCertificateLevel(CertificateLevel.valueOf(cl.optString("defaultCertificateLevel"))).build();
        BiFunction<EidClient, Json.Obj, Object> op = WireVectorTest.OPS.get(call.optString("method"));
        assertNotNull("method " + call.optString("method"), op);
        Object result;
        try {
            result = op.apply(client, call.optObj("args") == null ? new Json.Obj() : call.optObj("args"));
        } catch (EidException e) {
            result = e;
        }
        assertEquals("one request", 1, seen.size());
        EidHttpRequest r = seen.get(0);
        assertEquals("method", req.optString("method"), r.method());
        String q = r.uri().getRawQuery();
        assertEquals("path", req.optString("path"), r.uri().getRawPath() + (q == null ? "" : "?" + q));
        Json.Obj wh = req.optObj("headers");
        for (String k : wh.keySet()) {
            String got = r.headers().get(k);
            if (k.equals("Content-Type") && got != null) got = got.split(";", 2)[0].trim();
            assertEquals("header " + k, wh.optString(k), got);
        }
        byte[] raw = r.body();
        Object sent = raw == null || raw.length == 0 ? Json.NULL : Json.parse(raw);
        Object got = raw == null || raw.length == 0 ? Json.NULL : Json.parse(raw);
        Json.Obj vol = req.optObj("volatile");
        if (vol != null) {
            for (String ptr : vol.keySet()) {
                Object val = pointerGet(got, ptr);
                assertEquals("volatile format", "base64:64", vol.optString(ptr));
                assertTrue("volatile " + ptr + ": " + val, val instanceof String && ((String) val).matches("[A-Za-z0-9+/]+={0,2}")
                    && Base64.getDecoder().decode((String) val).length == 64);
                pointerSet(got, ptr, "$volatile");
            }
        }
        Object wantBody = req.has("body") ? req.get("body") : Json.NULL;
        FakeRp.assertJsonEquals("request body", FakeRp.text(wantBody), FakeRp.text(got));
        Object out;
        if (result instanceof EidException) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("error", errJson((EidException) result));
            out = m;
        } else {
            Object rb = res.get("body");
            out = wireExpect(result, rb instanceof Json.Obj && ((Json.Obj) rb).has("expiresAt"));
        }
        Object want = resolve(c.get("expect"), sent);
        FakeRp.assertJsonEquals("result", FakeRp.text(want), FakeRp.text(out));
    }

    // ── interactions, ACSP ──

    @Test
    public void interactions() {
        Json.Obj f = json("interactions_golden.json");
        assertEquals("interactions/1", f.optString("version"));
        List<Object> cases = f.optArr("cases");
        assertTrue(cases.size() >= 8);
        runAll("interactions", cases, c -> {
            List<Interaction> in = new ArrayList<>();
            for (Object o : c.optArr("interactions")) {
                Json.Obj i = (Json.Obj) o;
                in.add(new Interaction(i.optString("type"), i.optStringOrNull("displayText60"), i.optStringOrNull("displayText200")));
            }
            String b64 = EidCrypto.interactionsToBase64(in);
            assertEquals(c.optString("base64"), b64);
            assertEquals(c.optString("json"), new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8));
            assertTrue(Arrays.equals(EidCrypto.utf8(c.optString("json")), Base64.getDecoder().decode(c.optString("base64"))));
        });
    }

    @Test
    public void acspV2() {
        Json.Obj f = json("acsp_v2.json");
        assertEquals("acsp-v2/1", f.optString("version"));
        List<Object> cases = f.optArr("cases");
        assertTrue(cases.size() >= 3);
        runAll("acsp", cases, c -> {
            Json.Obj p = c.optObj("params");
            AcspV2Params in = new AcspV2Params(p.optString("schemeName"), p.optString("serverRandom"), p.optString("rpChallenge"),
                p.optString("userChallenge"), p.optString("relyingPartyName"), p.optString("brokeredRpName"), p.optString("interactions"),
                p.optString("interactionTypeUsed"), p.optString("initialCallbackUrl"), p.optString("flowType"));
            assertEquals(c.optString("payload"), new String(Acsp.buildV2Payload(in), StandardCharsets.UTF_8));
            assertEquals(c.optString("digestB64"), Base64.getEncoder().encodeToString(Acsp.v2Digest(in, c.optString("hashAlgorithm"))));
        });
    }

    // ── OCSP ──

    @Test
    public void ocsp() {
        Json.Obj f = json("ocsp/cases.json");
        assertEquals("ocsp-checker/1", f.optString("version"));
        List<Object> cases = f.optArr("cases");
        assertEquals("cases", 17, cases.size());
        runAll("ocsp", cases, ConformanceTest::ocspCase);
    }

    /** A transport answering from the case's replay map ("METHOD URL" → status, content type, body); else 404. */
    static EidTransport replay(Json.Obj http, List<EidHttpRequest> seen) {
        return r -> {
            seen.add(r);
            Json.Obj rep = http == null ? null : http.optObj(r.method() + " " + r.uri());
            if (rep == null) return new EidHttpResponse(404, Map.of(), new byte[0]);
            byte[] body = Base64.getDecoder().decode(rep.optString("bodyB64"));
            // The transport contract: at most maxResponseBytes + 1 body bytes.
            if (body.length > r.maxResponseBytes() + 1) body = Arrays.copyOf(body, (int) r.maxResponseBytes() + 1);
            Map<String, List<String>> h = new LinkedHashMap<>();
            if (!rep.optString("contentType").isEmpty()) h.put("Content-Type", List.of(rep.optString("contentType")));
            return new EidHttpResponse((int) rep.optLong("status", 0), h, body);
        };
    }

    private static void ocspCase(Json.Obj c) {
        Instant now = Instant.parse(c.optString("now"));
        List<EidHttpRequest> seen = new ArrayList<>();
        OcspRevocationChecker check = OcspRevocationChecker.builder().transport(replay(c.optObj("http"), seen))
            .clock(Clock.fixed(now, ZoneOffset.UTC)).build();
        X509Certificate leaf = cert(bytes(c.optString("certificate")));
        X509Certificate issuer = cert(bytes(c.optString("issuer")));
        String status;
        String kind = "";
        try {
            status = check.check(leaf, issuer).wireName();
        } catch (EidException.Ocsp e) {
            status = RevocationStatus.UNKNOWN.wireName();
            kind = e.kind().wireName();
        }
        Json.Obj exp = c.optObj("expect");
        assertEquals("status (" + kind + ")", exp.optString("status"), status);
        assertEquals("errorKind", exp.optString("errorKind"), kind);
        assertFalse("requests", seen.isEmpty());
        for (EidHttpRequest r : seen) {
            assertEquals("POST", r.method());
            assertEquals("application/ocsp-request", r.headers().get("Content-Type"));
            assertTrue(r.timeout().compareTo(OcspRevocationChecker.REQUEST_TIMEOUT) <= 0);
            assertEquals(OcspRevocationChecker.MAX_RESPONSE_BYTES, r.maxResponseBytes());
        }
    }
}
