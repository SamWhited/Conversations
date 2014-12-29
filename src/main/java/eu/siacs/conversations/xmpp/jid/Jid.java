package eu.siacs.conversations.xmpp.jid;

import net.java.otr4j.session.SessionID;

import java.net.IDN;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import gnu.inet.encoding.Stringprep;
import gnu.inet.encoding.StringprepException;

/**
 * The `Jid' class provides an immutable representation of a JID as specified in RFC 6122 with support for escaping of
 * disallowed characters in the localpart as specified in XEP-0106.
 */
public final class Jid {

	private static final Map<String, String> nodeEscape;

	static {
		// See XEP-0106 Version 1.1 § 3.2 Table 1
		nodeEscape = Collections.unmodifiableMap(new HashMap<String, String>() {{
			put(" ",  "\\20");
			put("\"", "\\22");
			put("&",  "\\26");
			put("'",  "\\27");
			put("/",  "\\2f");
			put(":",  "\\3a");
			put("<",  "\\3c");
			put(">",  "\\3e");
			put("@",  "\\40");
			// Special case; See XEP-0106 § 4.3 Exceptions
			put("\\5c", "\\5c5c");
		}});
	}

	private final String localpart;
	private final String domainpart;
	private final String resourcepart;

	// It's much more efficient to store the ful JID as well as the parts instead of figuring them
	// all out every time (since some characters are displayed but aren't used for comparisons).
	private final String displayJid;

	public String getLocalpart() {
		return localpart;
	}

	public String getDomainpart() {
		return IDN.toUnicode(domainpart);
	}

	public String getResourcepart() {
		return resourcepart;
	}

	public static Jid fromSessionID(final SessionID id) throws InvalidJidException{
		if (id.getUserID().isEmpty()) {
			return Jid.fromString(id.getAccountID());
		} else {
			return Jid.fromString(id.getAccountID()+"/"+id.getUserID());
		}
	}

	public static Jid fromString(final String jid) throws InvalidJidException {
		return new Jid(jid);
	}

	public static Jid fromParts(final String localpart,
			final String domainpart,
			final String resourcepart) throws InvalidJidException {
		String out;
		if (localpart == null || localpart.isEmpty()) {
			out = domainpart;
		} else {
			out = localpart + "@" + domainpart;
		}
		if (resourcepart != null && !resourcepart.isEmpty()) {
			out = out + "/" + resourcepart;
		}
		return new Jid(out);
	}

	private Jid(final String jid) throws InvalidJidException {
		// Hackish Android way to count the number of chars in a string... should work everywhere.
		final int atCount = jid.length() - jid.replace("@", "").length();
		final int slashCount = jid.length() - jid.replace("/", "").length();

		// Throw an error if there's anything obvious wrong with the JID...
		if (jid.isEmpty() || jid.length() > 3071) {
			throw new InvalidJidException(InvalidJidException.INVALID_LENGTH);
		}

		// Go ahead and check if the localpart or resourcepart is empty.
		if (jid.startsWith("@") || (jid.endsWith("@") && slashCount == 0) || jid.startsWith("/") || (jid.endsWith("/") && slashCount < 2)) {
			throw new InvalidJidException(InvalidJidException.INVALID_CHARACTER);
		}

		String finaljid;

		final int domainpartStart;
		final int atLoc = jid.indexOf("@");
		final int slashLoc = jid.indexOf("/");
		// If there is no "@" in the JID (eg. "example.net" or "example.net/resource")
		// or there are one or more "@" signs but they're all in the resourcepart (eg. "example.net/@/rp@"):
		if (atCount == 0 || (atCount > 0 && slashLoc != -1 && atLoc > slashLoc)) {
			localpart = "";
			finaljid = "";
			domainpartStart = 0;
		} else {
			final String lp = jid.substring(0, atLoc);
			try {
				localpart = Stringprep.nodeprep(nodeEscape(lp));
				// From XEP-0106 § 3.2 Escaping Transformations and § 4.1 Native Processing:
				// The character sequence \20 MUST NOT be the first or last character of an escaped node identifier.
				if (localpart.startsWith("\\20") || localpart.endsWith("\\20")) {
					throw new InvalidJidException("Escaped JID MUST NOT begin or end with \\20");
				}
			} catch (final StringprepException e) {
				throw new InvalidJidException(InvalidJidException.STRINGPREP_FAIL, e);
			}
			if (localpart.isEmpty() || localpart.length() > 1023) {
				throw new InvalidJidException(InvalidJidException.INVALID_PART_LENGTH);
			}
			domainpartStart = atLoc + 1;
			finaljid = lp + "@";
		}

		final String dp;
		if (slashCount > 0) {
			final String rp = jid.substring(slashLoc + 1, jid.length());
			try {
				resourcepart = Stringprep.resourceprep(rp);
			} catch (final StringprepException e) {
				throw new InvalidJidException(InvalidJidException.STRINGPREP_FAIL, e);
			}
			if (resourcepart.isEmpty() || resourcepart.length() > 1023) {
				throw new InvalidJidException(InvalidJidException.INVALID_PART_LENGTH);
			}
			dp = IDN.toUnicode(jid.substring(domainpartStart, slashLoc), IDN.USE_STD3_ASCII_RULES);
			finaljid = finaljid + dp + "/" + rp;
		} else {
			resourcepart = "";
			dp = IDN.toUnicode(jid.substring(domainpartStart, jid.length()),
					IDN.USE_STD3_ASCII_RULES);
			finaljid = finaljid + dp;
		}

		// Remove trailing "." before storing the domain part.
		if (dp.endsWith(".")) {
			try {
				domainpart = IDN.toASCII(dp.substring(0, dp.length() - 1), IDN.USE_STD3_ASCII_RULES);
			} catch (final IllegalArgumentException e) {
				throw new InvalidJidException(e);
			}
		} else {
			try {
				domainpart = IDN.toASCII(dp, IDN.USE_STD3_ASCII_RULES);
			} catch (final IllegalArgumentException e) {
				throw new InvalidJidException(e);
			}
		}

		// TODO: Find a proper domain validation library; validate individual parts, separators, etc.
		if (domainpart.isEmpty() || domainpart.length() > 1023) {
			throw new InvalidJidException(InvalidJidException.INVALID_PART_LENGTH);
		}

		this.displayJid = finaljid;
	}

	public Jid toBareJid() {
		try {
			return resourcepart.isEmpty() ? this : fromParts(localpart, domainpart, "");
		} catch (final InvalidJidException e) {
			// This should never happen.
			return null;
		}
	}

	public Jid toDomainJid() {
		try {
			return resourcepart.isEmpty() && localpart.isEmpty() ? this : fromString(getDomainpart());
		} catch (final InvalidJidException e) {
			// This should never happen.
			return null;
		}
	}

	@Override
	public String toString() {
		return displayJid;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;

		final Jid jid = (Jid) o;

		return jid.hashCode() == this.hashCode();
	}

	@Override
	public int hashCode() {
		int result = localpart.hashCode();
		result = 31 * result + domainpart.hashCode();
		result = 31 * result + resourcepart.hashCode();
		return result;
	}

	public boolean hasLocalpart() {
		return !localpart.isEmpty();
	}

	public boolean isBareJid() {
		return this.resourcepart.isEmpty();
	}

	public boolean isDomainJid() {
		return !this.hasLocalpart();
	}

	private static String nodeEscape(final String localpart) {
		// TODO: There is probably a more efficient way to do this. StringBuilder and a pre-compiled static Matcher?
		String escaped = localpart;
		for (final Map.Entry<String, String> entry : nodeEscape.entrySet()) {
			escaped = escaped.replaceAll(entry.getKey(), entry.getValue());
		}
		return escaped;
	}
}
