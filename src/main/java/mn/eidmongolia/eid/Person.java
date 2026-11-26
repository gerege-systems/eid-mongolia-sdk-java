package mn.eidmongolia.eid;

/**
 * The session's person block (CA registry; Go {@code Person}). NOT part of the signature — trust it only after the
 * validator accepted the response and {@code civilId} matches the certificate's SERIALNUMBER (PNOMN-&lt;civilId&gt;).
 * lastName = patronymic (in the certificate), familyName = clan name (not in the certificate). Unknown fields are "",
 * unknown geId 0.
 *
 * @param birthDate YYYY-MM-DD
 * @param gender M | F | X
 * @param nationality ISO 3166-1 alpha-3 / ICAO 9303 code, passed through unchecked; "" when unknown
 */
public record Person(String firstName, String lastName, String familyName, String firstNameEn, String lastNameEn,
    String civilId, String regNo, String birthDate, String gender, long geId, String nationality) {
}
