/**
 * 
 */
package de.fom.inf;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author alunk
 *
 *         A very simple example of an AES encryptor
 */
public class RawAESEncryptor {

	private byte[] secretKey;

	public RawAESEncryptor(byte[] secret) throws IllegalArgumentException {

		if (secret.length != 16 && secret.length != 24 && secret.length != 32)
			throw new IllegalArgumentException("Invalid key size");

		secretKey = new byte[secret.length];

		System.arraycopy(secret, 0, secretKey, 0, secret.length);
	}

	/**
	 * Encrypt data using AES
	 * 
	 * @param data
	 * @return
	 * @throws Exception
	 */
	public byte[] encipher(byte[] data) throws Exception {
		SecretKeySpec aesKeySpec = new SecretKeySpec(secretKey, "AES");

		Cipher aesCipher = Cipher.getInstance("AES");

		aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);

		byte[] encryptedContent = aesCipher.doFinal(data);

		return encryptedContent;
	}

	/**
	 * Decrypt given cipher text
	 * 
	 * @param cipherText
	 * @return
	 * @throws Exception
	 */
	public byte[] decipher(byte[] cipherText) throws Exception {
		SecretKeySpec aesKeySpec = new SecretKeySpec(secretKey, "AES");

		Cipher aesCipher = Cipher.getInstance("AES");

		aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);

		byte[] decryptedContent = aesCipher.doFinal(cipherText);

		return decryptedContent;
	}

}
