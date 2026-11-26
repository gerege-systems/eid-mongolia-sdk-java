package mn.eidmongolia.eid;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeMap;

/**
 * The citizen's PKI dashboard ({@link EidClient#person()}, Go {@code PersonService}, TS {@code PersonApi}; CA
 * docs/EID_PERSON_PKI.md): certificates, devices, activity, summary counts, children. The RP needs PKI_READ (granted by
 * the admin) AND the citizen must have signed in to your RP within the last 24 h — otherwise
 * {@link EidException.Forbidden} (403); unknown citizen → {@link EidException.Api} 404. Every result carries the server's
 * raw JSON.
 */
public final class PersonService {
    private final RpHttp http;

    PersonService(RpHttp http) {
        this.http = http;
    }

    /** All of the citizen's certificates with status counts. */
    public PersonCertificates certificates(String personEtsi) {
        String op = "GET /certificates/etsi/…";
        RpHttp.Result r = http.getJson(Routes.PERSON_CERTIFICATES.expand(personEtsi), null);
        Json.Obj o = r.obj(op);
        List<PersonCertificate> l = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "certificates")) l.add(PersonCertificate.of(x, op));
        return new PersonCertificates(o.optString("personEtsi"), CertCounts.of(Dto.obj(o, "counts")), Collections.unmodifiableList(l),
            Dto.raw(r));
    }

    /** The citizen's devices (active and inactive). */
    public PersonDevices devices(String personEtsi) {
        String op = "GET /devices/etsi/…";
        RpHttp.Result r = http.getJson(Routes.PERSON_DEVICES.expand(personEtsi), null);
        Json.Obj o = r.obj(op);
        List<PersonDevice> l = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "devices")) l.add(PersonDevice.of(x, op));
        return new PersonDevices(o.optString("personEtsi"), Collections.unmodifiableList(l), Dto.integer(o, "activeCount"),
            Dto.integer(o, "total"), Dto.raw(r));
    }

    /** The citizen's activity with your RP; {@code q} null = the server's defaults. */
    public PersonActivity activity(String personEtsi, ActivityQuery q) {
        String path = Routes.PERSON_ACTIVITY.expand(personEtsi);
        if (q != null) {
            // Go url.Values.Encode: keys sorted, QueryEscape.
            TreeMap<String, String> v = new TreeMap<>();
            if (q.flow() != null && !q.flow().isEmpty()) v.put("flow", q.flow());
            if (q.limit() > 0) v.put("limit", Integer.toString(q.limit()));
            if (q.offset() > 0) v.put("offset", Integer.toString(q.offset()));
            StringBuilder qs = new StringBuilder();
            for (var e : v.entrySet()) {
                if (qs.length() > 0) qs.append('&');
                qs.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8)).append('=')
                    .append(URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8));
            }
            if (qs.length() > 0) path += "?" + qs;
        }
        String op = "GET /rp/activity/etsi/…";
        RpHttp.Result r = http.getJson(path, null);
        Json.Obj o = r.obj(op);
        List<ActivityItem> l = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "sessions")) l.add(ActivityItem.of(x, op));
        return new PersonActivity(o.optString("personEtsi"), ActivityCounts.of(Dto.obj(o, "counts")), Collections.unmodifiableList(l),
            Dto.integer(o, "total"), Dto.integer(o, "limit"), Dto.integer(o, "offset"), Dto.raw(r));
    }

    /** The dashboard's counts in one call. */
    public PersonSummary summary(String personEtsi) {
        RpHttp.Result r = http.getJson(Routes.PERSON_SUMMARY.expand(personEtsi), null);
        Json.Obj o = r.obj("GET /person/summary/etsi/…");
        return new PersonSummary(o.optString("personEtsi"), o.optString("firstName"), o.optString("lastName"),
            o.optString("familyName"), o.optString("nationality"), CertCounts.of(Dto.obj(o, "certificates")),
            ActivityCounts.of(Dto.obj(o, "activity")), Dto.integer(o, "devicesActive"), Dto.integer(o, "devicesTotal"),
            Dto.integer(o, "representationCount"), Dto.raw(r));
    }

    /** The children in the citizen's guardianship (read only). */
    public PersonChildren children(String personEtsi) {
        String op = "GET /person/children/etsi/…";
        RpHttp.Result r = http.getJson(Routes.PERSON_CHILDREN.expand(personEtsi), null);
        Json.Obj o = r.obj(op);
        List<PersonChild> l = new ArrayList<>();
        for (Json.Obj x : Dto.objects(o, "children")) l.add(PersonChild.of(x, op));
        return new PersonChildren(Collections.unmodifiableList(l), Dto.raw(r));
    }
}
