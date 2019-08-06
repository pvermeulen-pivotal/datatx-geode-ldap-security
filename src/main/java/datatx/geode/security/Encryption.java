package datatx.geode.security;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Encryption {

	public static String encrypt(String plainText) throws EncryptionException {
		try {
			byte[] key = System.getProperty("key").getBytes();
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			byte[] cipherText = cipher.doFinal(plainText.getBytes("UTF8"));
			return new String(Base64.getEncoder().encode(cipherText), "UTF-8");
		} catch (Exception e) {
			throw new EncryptionException("Failed to process peer authorization.");
		}
	}

	public static String decrypt(String encryptedText) throws EncryptionException {
		try {
			byte[] key = System.getProperty("key").getBytes();
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			byte[] cipherText = Base64.getDecoder().decode(encryptedText.getBytes("UTF8"));
			return new String(cipher.doFinal(cipherText), "UTF-8");
		} catch (Exception e) {
			throw new EncryptionException("Failed to process peer authorization.");
		}
	}

	public static class EncryptionException extends Exception {
		private static final long serialVersionUID = 1677450115135240761L;

		public EncryptionException(String msg) {
			super(msg);
		}
	}

	public static void main(String[] args) throws Exception {
		if (args != null && args.length == 2) {
			if (args[0].equalsIgnoreCase("ENCRYPT")) {
				encrypt(args[1]);
			} else if (args[0].equalsIgnoreCase("DECRYPT")) {
				decrypt(args[1]);
			} else {
				throw new RuntimeException("Invalid command; Valid commands are encrypt and decrypt");
			}
		} else {
			throw new RuntimeException("Invalid arguments; Valid arguments encrypt password or decrypt password");
		}
	}
}
