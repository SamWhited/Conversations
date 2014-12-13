package eu.siacs.conversations.crypto.sasl;

import android.util.Base64;
import android.util.LruCache;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;

import eu.siacs.conversations.entities.Account;
import eu.siacs.conversations.utils.CryptoHelper;
import eu.siacs.conversations.xml.TagWriter;

public class ScramSha1 extends SaslMechanism {
	final private String GS2_HEADER;
	private String clientFirstMessageBare;
	final private String clientNonce;
	final private SSLSession sslSession;
	private byte[] serverSignature = null;
	private static final HMac HMAC;
	private static final Digest DIGEST;
	private static final byte[] CLIENT_KEY_BYTES = "Client Key".getBytes();
	private static final byte[] SERVER_KEY_BYTES = "Server Key".getBytes();

	public static class KeyPair {
		final public byte[] clientKey;
		final public byte[] serverKey;

		public KeyPair(final byte[] clientKey, final byte[] serverKey) {
			this.clientKey = clientKey;
			this.serverKey = serverKey;
		}
	}

	private static final LruCache<String, KeyPair> CACHE;

	static {
		DIGEST = new SHA1Digest();
		HMAC = new HMac(new SHA1Digest());
		CACHE = new LruCache<String, KeyPair>(10) {
			protected KeyPair create(final String k) {
				// Map keys are "bytesToHex(JID),bytesToHex(password),bytesToHex(salt),iterations".
				// Changing any of these values forces a cache miss. `CryptoHelper.bytesToHex()'
				// is applied to prevent commas in the strings breaking things.
				final String[] kparts = k.split(",", 4);
				try {
					final byte[] saltedPassword, serverKey, clientKey;
					saltedPassword = hi(CryptoHelper.hexToString(kparts[1]).getBytes(),
							Base64.decode(CryptoHelper.hexToString(kparts[2]), Base64.DEFAULT), Integer.valueOf(kparts[3]));
					serverKey = hmac(saltedPassword, SERVER_KEY_BYTES);
					clientKey = hmac(saltedPassword, CLIENT_KEY_BYTES);

					return new KeyPair(clientKey, serverKey);
				} catch (final InvalidKeyException | NumberFormatException e) {
					return null;
				}
			}
		};
	}

	private State state = State.INITIAL;

	public ScramSha1(final TagWriter tagWriter, final Account account, final SecureRandom rng, final SSLSession sslSession) {
		super(tagWriter, account, rng);

		// This nonce should be different for each authentication attempt.
		clientNonce = new BigInteger(100, this.rng).toString(32);
		clientFirstMessageBare = "";
		if (sslSession != null) {
			this.sslSession = sslSession;
			GS2_HEADER = "p=tls-server-end-point,,";
		} else {
			this.sslSession = null;
			GS2_HEADER = "y,,";
		}
	}

	@Override
	public int getPriority() {
		if (this.sslSession != null) {
			return 25;
		} else {
			return 20;
		}
	}

	@Override
	public String getMechanism() {
		if (this.sslSession != null) {
			return "SCRAM-SHA-1-PLUS";
		} else {
			return "SCRAM-SHA-1";
		}
	}

	@Override
	public String getClientFirstMessage() {
		if (clientFirstMessageBare.isEmpty() && state == State.INITIAL) {
			clientFirstMessageBare = "n=" + CryptoHelper.saslEscape(CryptoHelper.saslPrep(account.getUsername())) +
				",r=" + this.clientNonce;
			state = State.AUTH_TEXT_SENT;
		}
		return Base64.encodeToString(
				(GS2_HEADER + clientFirstMessageBare).getBytes(Charset.defaultCharset()),
				Base64.NO_WRAP);
	}

	@Override
	public String getResponse(final String challenge) throws AuthenticationException {
		switch (state) {
			case AUTH_TEXT_SENT:
				if (challenge == null) {
					throw new AuthenticationException("challenge can not be null");
				}
				final byte[] serverFirstMessage = Base64.decode(challenge, Base64.DEFAULT);
				final Tokenizer tokenizer = new Tokenizer(serverFirstMessage);
				String nonce = "";
				int iterationCount = -1;
				String salt = "";
				for (final String token : tokenizer) {
					if (token.charAt(1) == '=') {
						switch (token.charAt(0)) {
							case 'i':
								try {
									iterationCount = Integer.parseInt(token.substring(2));
								} catch (final NumberFormatException e) {
									throw new AuthenticationException(e);
								}
								break;
							case 's':
								salt = token.substring(2);
								break;
							case 'r':
								nonce = token.substring(2);
								break;
							case 'm':
								/*
								 * RFC 5802:
								 * m: This attribute is reserved for future extensibility.  In this
								 * version of SCRAM, its presence in a client or a server message
								 * MUST cause authentication failure when the attribute is parsed by
								 * the other end.
								 */
								throw new AuthenticationException("Server sent reserved token: `m'");
						}
					}
				}

				if (iterationCount < 0) {
					throw new AuthenticationException("Server did not send iteration count");
				}
				if (nonce.isEmpty() || !nonce.startsWith(clientNonce)) {
					throw new AuthenticationException("Server nonce does not contain client nonce: " + nonce);
				}
				if (salt.isEmpty()) {
					throw new AuthenticationException("Server sent empty salt");
				}

				byte[] cbindData = {};
				if (sslSession != null) {
					try {
						final String usealgo;
						final Certificate cert = sslSession.getPeerCertificates()[0];
						final String algo = cert.getPublicKey().getAlgorithm();
						// RFC5929 §4.1
						// if the certificate's signatureAlgorithm uses a single hash
						// function, and that hash function is either MD5 [RFC1321] or SHA-1
						// [RFC3174], then use SHA-256 [FIPS-180-3];
						if (algo.equals("MD5") || algo.equals("SHA-1")) {
							usealgo = "SHA-256";
						} else {
							// RFC5929 §4.1
							// if the certificate's signatureAlgorithm uses a single hash
							// function and that hash function neither MD5 nor SHA-1, then use
							// the hash function associated with the certificate's
							// signatureAlgorithm;
							usealgo = algo;
						}
						final MessageDigest md = MessageDigest.getInstance(usealgo);
						final byte[] der = cert.getEncoded();
						md.update(der);
						cbindData = md.digest();
					} catch (final SSLPeerUnverifiedException | CertificateEncodingException | NoSuchAlgorithmException ignored) {
						// Can not get channel binding data. Server will fail on next step.
					}
				}

				final int gs2Len = GS2_HEADER.getBytes().length;
				final byte[] cMessage = new byte[gs2Len + cbindData.length];
				System.arraycopy(GS2_HEADER.getBytes(), 0, cMessage, 0, gs2Len);
				System.arraycopy(cbindData, 0, cMessage, gs2Len, cbindData.length);

				final String clientFinalMessageWithoutProof = "c=" + Base64.encodeToString(cMessage, Base64.NO_WRAP)
					+ ",r=" + nonce;
				final byte[] authMessage = (clientFirstMessageBare + ',' + new String(serverFirstMessage) + ','
						+ clientFinalMessageWithoutProof).getBytes();

				// Map keys are "bytesToHex(JID),bytesToHex(password),bytesToHex(salt),iterations".
				final KeyPair keys = CACHE.get(
						CryptoHelper.bytesToHex(account.getJid().toBareJid().toString().getBytes()) + ","
						+ CryptoHelper.bytesToHex(account.getPassword().getBytes()) + ","
						+ CryptoHelper.bytesToHex(salt.getBytes()) + ","
						+ String.valueOf(iterationCount)
						);
				if (keys == null) {
					throw new AuthenticationException("Invalid keys generated");
				}
				final byte[] clientSignature;
				serverSignature = hmac(keys.serverKey, authMessage);
				final byte[] storedKey = digest(keys.clientKey);

				clientSignature = hmac(storedKey, authMessage);

				final byte[] clientProof = new byte[keys.clientKey.length];

				for (int i = 0; i < clientProof.length; i++) {
					clientProof[i] = (byte) (keys.clientKey[i] ^ clientSignature[i]);
				}


				final String clientFinalMessage = clientFinalMessageWithoutProof + ",p=" +
					Base64.encodeToString(clientProof, Base64.NO_WRAP);
				state = State.RESPONSE_SENT;
				return Base64.encodeToString(clientFinalMessage.getBytes(), Base64.NO_WRAP);
			case RESPONSE_SENT:
				final String clientCalculatedServerFinalMessage = "v=" +
					Base64.encodeToString(serverSignature, Base64.NO_WRAP);
				if (challenge == null || !clientCalculatedServerFinalMessage.equals(new String(Base64.decode(challenge, Base64.DEFAULT)))) {
					throw new AuthenticationException("Server final message does not match calculated final message");
				}
				state = State.VALID_SERVER_RESPONSE;
				return "";
			default:
				throw new InvalidStateException(state);
		}
	}

	public static synchronized byte[] hmac(final byte[] key, final byte[] input) {
		HMAC.init(new KeyParameter(key));
		HMAC.update(input, 0, input.length);
		final byte[] out = new byte[HMAC.getMacSize()];
		HMAC.doFinal(out, 0);
		return out;
	}

	public static synchronized byte[] digest(byte[] bytes) {
		DIGEST.reset();
		DIGEST.update(bytes, 0, bytes.length);
		final byte[] out = new byte[DIGEST.getDigestSize()];
		DIGEST.doFinal(out, 0);
		return out;
	}

	/*
	 * Hi() is, essentially, PBKDF2 [RFC2898] with HMAC() as the
	 * pseudorandom function (PRF) and with dkLen == output length of
	 * HMAC() == output length of H().
	 */
	private static synchronized byte[] hi(final byte[] key, final byte[] salt, final int iterations)
		throws InvalidKeyException {
		byte[] u = hmac(key, CryptoHelper.concatenateByteArrays(salt, CryptoHelper.ONE));
		byte[] out = u.clone();
		for (int i = 1; i < iterations; i++) {
			u = hmac(key, u);
			for (int j = 0; j < u.length; j++) {
				out[j] ^= u[j];
			}
		}
		return out;
	}
}
