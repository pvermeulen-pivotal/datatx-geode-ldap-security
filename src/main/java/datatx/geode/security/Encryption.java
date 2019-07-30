package datatx.geode.security;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

	public static String encrypt(String plainText) throws PeerAuthException {
		try {
			byte[] key = System.getProperty("key").getBytes();
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
			return new String(Base64.getEncoder().encode(cipherText), "UTF-8");

		} catch (Exception e) {
			throw new PeerAuthException("Failed to process peer authorization.");
		}

	}

	public static String decrypt(String encryptedText) throws PeerAuthException {
		try {
			byte[] key = System.getProperty("key").getBytes();
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] cipherText = Base64.getDecoder().decode(encryptedText.getBytes("UTF8"));
			return new String(cipher.doFinal(cipherText), "UTF-8");
		} catch (Exception e) {
			throw new PeerAuthException("Failed to process peer authorization.");
		}
	}

	public static class PeerAuthException extends Exception {
		private static final long serialVersionUID = 1677450115135240761L;
		public PeerAuthException(String msg) {
			super(msg);
		}
	}
}
