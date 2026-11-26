package mn.eidmongolia.eid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BiFunction;
import mn.eidmongolia.eid.pades.Medium;
import mn.eidmongolia.eid.pades.Registration;
import org.junit.Test;

/**
 * Every RP-API method of this package against wire vectors ({@link WireVectors}): HTTP method, path, query and the
 * request-body JSON (semantic), then the canned response's parsed result or typed error. The vectors name their Go/TS
 * source test; the conformance corpus plugs in through {@link #SOURCES}.
 */
public class WireVectorTest {
    /** TODO(rp-conformance-v1): add the vendored conformance corpus source here (see {@link WireVectors}). */
    static final List<WireVectors.Source> SOURCES = List.of(WireVectors.LOCAL);

    /** op name → the call (client, input) → result. */
    static final Map<String, BiFunction<EidClient, Json.Obj, Object>> OPS = new LinkedHashMap<>();

    static {
        OPS.put("auth.notificationByEtsi", (c, in) -> c.auth().notificationByEtsi(in.optString("id"), ix(in), authOpts(in)));
        OPS.put("auth.notificationByDocument", (c, in) -> c.auth().notificationByDocument(in.optString("documentNumber"), ix(in), authOpts(in)));
        OPS.put("auth.deviceLinkAnonymous", (c, in) -> c.auth().deviceLinkAnonymous(ix(in), authOpts(in)));
        OPS.put("auth.deviceLinkByEtsi", (c, in) -> c.auth().deviceLinkByEtsi(in.optString("id"), ix(in), authOpts(in)));
        OPS.put("sign.digestByEtsi", (c, in) -> c.sign().digestByEtsi(in.optString("id"), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.digestByDocument", (c, in) -> c.sign().digestByDocument(in.optString("documentNumber"), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.textByEtsi", (c, in) -> c.sign().textByEtsi(in.optString("id"), in.optString("text"), ix(in), signOpts(in)));
        OPS.put("sign.deviceLinkByEtsi", (c, in) -> c.sign().deviceLinkByEtsi(in.optString("id"), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.deviceLinkByDocument", (c, in) -> c.sign().deviceLinkByDocument(in.optString("documentNumber"), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.digestForSigner", (c, in) -> c.sign().digestForSigner(signer(in), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.deviceLinkForSigner", (c, in) -> c.sign().deviceLinkForSigner(signer(in), in.optString("digest"), ix(in), signOpts(in)));
        OPS.put("sign.certificateChoiceByEtsi", (c, in) -> c.sign().certificateChoiceByEtsi(in.optString("id"), ccOpts(in)));
        OPS.put("sign.certificateChoiceDeviceLink", (c, in) -> c.sign().certificateChoiceDeviceLink(ccOpts(in)));
        OPS.put("session.poll", (c, in) -> c.session().poll(in.optString("sessionId"), Duration.ofMillis(in.optLong("serverPollMs", 0))));
        OPS.put("pdf.registerSignature", (c, in) -> c.pdf().registerSignature(registration(in.optObj("registration"))));
    }

    @Test
    public void vectors() {
        Set<String> covered = new HashSet<>();
        int n = 0;
        for (WireVectors.Source src : SOURCES) {
            for (WireVectors.Vector v : src.vectors()) {
                run(v);
                covered.add(v.op());
                n++;
            }
        }
        assertTrue("vectors " + n, n >= 20);
        assertEquals("every operation has a vector", OPS.keySet(), covered);
    }

    private static void run(WireVectors.Vector v) {
        BiFunction<EidClient, Json.Obj, Object> op = OPS.get(v.op());
        assertNotNull(v + ": unknown op " + v.op(), op);
        FakeRp rp = FakeRp.reply(v.status(), FakeRp.text(v.responseBody()));
        Object result;
        try {
            result = op.apply(rp.client(), v.input() == null ? new Json.Obj() : v.input());
        } catch (EidException e) {
            result = e;
        }
        assertEquals(v + ": one request", 1, rp.seen.size());
        EidHttpRequest r = rp.last();
        assertEquals(v + ": method", v.method(), r.method());
        assertEquals(v + ": path", v.path(), FakeRp.path(r));
        assertEquals(v + ": query", v.query(), r.uri().getRawQuery());
        if (v.requestBody() == null) {
            assertNull(v + ": no body", r.body());
        } else {
            assertEquals(v + ": Content-Type", "application/json", r.headers().get("Content-Type"));
            FakeRp.assertJsonEquals(v + ": request body", FakeRp.text(v.requestBody()), rp.lastBody());
        }
        assertEquals("Bearer rp_sk_secret123", r.headers().get("Authorization"));

        Map<String, Object> proj = project(result);
        Json.Obj req = v.requestBody() instanceof Json.Obj ? (Json.Obj) v.requestBody() : null;
        Json.Obj actualReq = v.requestBody() == null ? null : rp.lastJson();
        for (String k : v.expect().keySet()) {
            Object want = v.expect().get(k);
            if (k.contains("=")) { // cross-check: a result field equals a request field
                String[] lr = k.split("=", 2);
                Object a = resolve(lr[0], proj, actualReq);
                Object b = resolve(lr[1], proj, actualReq);
                assertTrue(v + ": " + k, Boolean.TRUE.equals(want) && a != null && FakeRp.text(a).equals(FakeRp.text(b)));
                continue;
            }
            if (!proj.containsKey(k)) fail(v + ": result has no field " + k + " (" + proj.keySet() + "), result " + result);
            FakeRp.assertJsonEquals(v + ": " + k, FakeRp.text(want), FakeRp.text(proj.get(k)));
        }
        if (result instanceof EidException && !v.expect().has("error.class")) throw new AssertionError(v + ": unexpected", (EidException) result);
        assertFalse(req != null && rp.lastBody().contains("rp_sk_secret123"));
    }

    private static Object resolve(String ref, Map<String, Object> proj, Json.Obj req) {
        if (ref.startsWith("request.")) return find(req, ref.substring("request.".length()));
        return proj.get(ref);
    }

    /** The first member named k anywhere in the request body. */
    private static Object find(Object v, String k) {
        if (v instanceof Json.Obj) {
            Json.Obj o = (Json.Obj) v;
            if (o.has(k)) return o.get(k);
            for (Object x : o.values) {
                Object f = find(x, k);
                if (f != null) return f;
            }
        }
        return null;
    }

    // ── input mapping (the corpus format will use the same names) ──

    static List<Interaction> ix(Json.Obj in) {
        List<Object> a = in.optArr("interactions");
        if (a == null) return null;
        List<Interaction> out = new ArrayList<>();
        for (Object o : a) {
            Json.Obj i = (Json.Obj) o;
            out.add(new Interaction(i.optString("type"), i.optStringOrNull("displayText60"), i.optStringOrNull("displayText200")));
        }
        return out;
    }

    static AuthOptions authOpts(Json.Obj in) {
        Json.Obj o = in.optObj("options");
        if (o == null) return null;
        return AuthOptions.builder().certificateLevel(level(o)).callbackUrl(o.optStringOrNull("callbackUrl"))
            .onBehalfOf(o.optStringOrNull("onBehalfOf")).signatureAlgorithm(SignatureAlgorithm.fromWire(o.optString("signatureAlgorithm")))
            .hashAlgorithm(HashAlgorithm.fromWire(o.optString("hashAlgorithm"))).build();
    }

    static SignOptions signOpts(Json.Obj in) {
        Json.Obj o = in.optObj("options");
        if (o == null) return null;
        return SignOptions.builder().certificateLevel(level(o)).callbackUrl(o.optStringOrNull("callbackUrl"))
            .onBehalfOf(o.optStringOrNull("onBehalfOf")).fileName(o.optStringOrNull("fileName"))
            .signatureAlgorithm(SignatureAlgorithm.fromWire(o.optString("signatureAlgorithm")))
            .hashAlgorithm(HashAlgorithm.fromWire(o.optString("hashAlgorithm"))).build();
    }

    static CertChoiceOptions ccOpts(Json.Obj in) {
        Json.Obj o = in.optObj("options");
        if (o == null) return null;
        return CertChoiceOptions.builder().certificateLevel(level(o)).callbackUrl(o.optStringOrNull("callbackUrl")).build();
    }

    private static CertificateLevel level(Json.Obj o) {
        String s = o.optString("certificateLevel");
        return s.isEmpty() ? null : CertificateLevel.valueOf(s);
    }

    static SignerRef signer(Json.Obj in) {
        Json.Obj s = in.optObj("signer");
        return s == null ? null : new SignerRef(s.optString("documentNumber"), s.optStringOrNull("certChoiceSessionId"));
    }

    static Registration registration(Json.Obj r) {
        return new Registration(r.optString("docID"), (int) r.optLong("revIndex", 0),
            "phone".equals(r.optString("medium")) ? Medium.PHONE : "token".equals(r.optString("medium")) ? Medium.TOKEN : null,
            r.optStringOrNull("sessionID"), r.optString("cms"), r.optStringOrNull("fileName"), r.optStringOrNull("inSha256"),
            r.optStringOrNull("pageSha256"), r.optStringOrNull("sigRevSha256"), r.optStringOrNull("outSha256"),
            strings(r.optArr("priorCmsSha256")), strings(r.optArr("priorRevisionSha256")), r.optStringOrNull("onBehalfOf"),
            r.optStringOrNull("signerEtsi"), null);
    }

    private static List<String> strings(List<Object> a) {
        if (a == null) return null;
        List<String> out = new ArrayList<>();
        for (Object o : a) out.add((String) o);
        return out;
    }

    // ── result projection (flat, dotted names) ──

    static Map<String, Object> project(Object r) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (r instanceof EidException) {
            EidException e = (EidException) r;
            m.put("error.class", e.getClass().getSimpleName());
            m.put("error.code", e.code());
            m.put("error.status", e.status());
        } else if (r instanceof NotificationSession) {
            NotificationSession s = (NotificationSession) r;
            m.put("sessionId", s.sessionId());
            m.put("vc", s.vc());
            m.put("rpChallenge", s.rpChallenge());
            m.put("expiresAt", iso(s.expiresAt()));
            acsp(m, s.acsp());
            sign(m, s.sign());
        } else if (r instanceof DeviceLinkSession) {
            DeviceLinkSession s = (DeviceLinkSession) r;
            m.put("sessionId", s.sessionId());
            m.put("vc", s.vc());
            m.put("rpChallenge", s.rpChallenge());
            m.put("sessionToken", s.sessionToken());
            m.put("sessionSecret", s.sessionSecret());
            m.put("deviceLinkBase", s.deviceLinkBase());
            m.put("sessionType", s.sessionType() == null ? Json.NULL : s.sessionType().wireName());
            m.put("relyingPartyName", s.relyingPartyName());
            m.put("callbackUrl", s.callbackUrl());
            m.put("receivedAt", iso(s.receivedAt()));
            m.put("expiresAt", iso(s.expiresAt()));
            acsp(m, s.acsp());
            sign(m, s.sign());
        } else if (r instanceof SessionResult) {
            SessionResult s = (SessionResult) r;
            m.put("state", s.state());
            m.put("endResult", s.endResult());
            m.put("documentNumber", s.documentNumber());
            m.put("certificateDerB64", s.certificateDerB64());
            m.put("certificateLevel", s.certificateLevel());
            m.put("signatureValueB64", s.signatureValueB64());
            m.put("signatureAlgorithm", s.signatureAlgorithm());
            m.put("signatureProtocol", s.signatureProtocol());
            m.put("serverRandom", s.serverRandom());
            m.put("userChallenge", s.userChallenge());
            m.put("flowType", s.flowType());
            m.put("initialCallbackUrl", nul(s.initialCallbackUrl()));
            m.put("interactionTypeUsed", s.interactionTypeUsed());
            SignatureAlgorithmParameters p = s.signatureAlgorithmParameters();
            m.put("signatureAlgorithmParameters", p == null ? Json.NULL : "<present>");
            if (p != null) {
                m.put("signatureAlgorithmParameters.hashAlgorithm", p.hashAlgorithm());
                m.put("signatureAlgorithmParameters.maskGenAlgorithm", p.maskGenAlgorithm());
                m.put("signatureAlgorithmParameters.maskGenHashAlgorithm", p.maskGenHashAlgorithm());
                m.put("signatureAlgorithmParameters.saltLength", nul(p.saltLength()));
                m.put("signatureAlgorithmParameters.trailerField", p.trailerField());
            }
            OrgResult o = s.onBehalfOf();
            m.put("onBehalfOf", o == null ? Json.NULL : "<present>");
            if (o != null) {
                m.put("onBehalfOf.orgEtsi", o.orgEtsi());
                m.put("onBehalfOf.orgName", o.orgName());
                m.put("onBehalfOf.role", o.role());
                m.put("onBehalfOf.roleLabel", o.roleLabel());
                m.put("onBehalfOf.rightType", o.rightType());
                m.put("onBehalfOf.rightTypeLabel", o.rightTypeLabel());
            }
            Person pe = s.person();
            m.put("person", pe == null ? Json.NULL : "<present>");
            if (pe != null) {
                m.put("person.firstName", pe.firstName());
                m.put("person.lastName", pe.lastName());
                m.put("person.familyName", pe.familyName());
                m.put("person.firstNameEn", pe.firstNameEn());
                m.put("person.lastNameEn", pe.lastNameEn());
                m.put("person.civilId", pe.civilId());
                m.put("person.regNo", pe.regNo());
                m.put("person.birthDate", pe.birthDate());
                m.put("person.gender", pe.gender());
                m.put("person.geId", pe.geId());
                m.put("person.nationality", pe.nationality());
            }
            TokenCertSessionBlock t = s.tokenCertificate();
            m.put("tokenCertificate", t == null ? Json.NULL : "<present>");
            if (t != null) {
                m.put("tokenCertificate.status", t.status());
                m.put("tokenCertificate.errorCode", t.errorCode());
                m.put("tokenCertificate.authSerialHex", t.authSerialHex());
                m.put("tokenCertificate.signSerialHex", t.signSerialHex());
            }
            m.put("presentationJws", nul(s.presentationJws()));
        } else if (r instanceof PdfSignatureRegistered) {
            PdfSignatureRegistered p = (PdfSignatureRegistered) r;
            m.put("docId", p.docId());
            m.put("revIndex", p.revIndex());
            m.put("registeredAt", p.registeredAt());
            m.put("verifyUrl", p.verifyUrl());
            m.put("created", p.created());
        }
        return m;
    }

    private static void acsp(Map<String, Object> m, AcspContext a) {
        m.put("acsp", a == null ? Json.NULL : "<present>");
        if (a == null) return;
        m.put("acsp.rpChallenge", a.rpChallenge());
        m.put("acsp.relyingPartyName", a.relyingPartyName());
        m.put("acsp.brokeredRpName", a.brokeredRpName());
        m.put("acsp.interactions", a.interactions());
        m.put("acsp.initialCallbackUrl", a.initialCallbackUrl());
        List<String> f = new ArrayList<>();
        for (FlowType t : a.flowTypes()) f.add(t.wireName());
        m.put("acsp.flowTypes", f);
        m.put("acsp.signatureAlgorithm", a.signatureAlgorithm().wireName());
        m.put("acsp.hashAlgorithm", a.hashAlgorithm().wireName());
    }

    private static void sign(Map<String, Object> m, SignContext s) {
        m.put("sign", s == null ? Json.NULL : "<present>");
        if (s == null) return;
        m.put("sign.digest", s.digest());
        m.put("sign.hashAlgorithm", s.hashAlgorithm().wireName());
        m.put("sign.signatureAlgorithm", s.signatureAlgorithm().wireName());
        m.put("sign.relyingPartyName", s.relyingPartyName());
        m.put("sign.interactions", s.interactions());
        m.put("sign.initialCallbackUrl", s.initialCallbackUrl());
    }

    private static Object iso(Instant t) {
        return t == null ? Json.NULL : t.toString();
    }

    private static Object nul(Object v) {
        return v == null ? Json.NULL : v;
    }
}
