package mn.eidmongolia.eid;

import java.util.Objects;

/**
 * An interaction shown on the citizen's phone (Go {@code Interaction}). displayTextAndPIN asks for the PIN and shows
 * a text (most common). displayText60 — up to 60 characters; displayText200 — up to 200.
 *
 * @param type "displayTextAndPIN" | "confirmationMessage" | "confirmationMessageAndVerificationCodeChoice"
 * @param displayText60 null or "" = omitted from the JSON
 * @param displayText200 null or "" = omitted from the JSON
 */
public record Interaction(String type, String displayText60, String displayText200) {
    public Interaction {
        Objects.requireNonNull(type, "type");
    }

    /** {@code displayTextAndPIN} with a ≤ 60 character text. */
    public static Interaction displayTextAndPin(String displayText60) {
        return new Interaction("displayTextAndPIN", displayText60, null);
    }

    /** {@code confirmationMessage} with a ≤ 200 character text. */
    public static Interaction confirmationMessage(String displayText200) {
        return new Interaction("confirmationMessage", null, displayText200);
    }
}
