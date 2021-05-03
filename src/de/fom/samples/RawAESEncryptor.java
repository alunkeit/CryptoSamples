/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 * @author alunk
 *
 *         A very simple example of an AES encryptor
 */
public class RawAESEncryptor
{

	private byte[] secretKey;

	private static Logger _logger = Logger.getLogger(RawAESEncryptor.class);

	public RawAESEncryptor(byte[] secret) throws IllegalArgumentException
	{

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
	public byte[] encipher(byte[] data) throws Exception
	{
		SecretKeySpec aesKeySpec = new SecretKeySpec(secretKey, "AES");

		Cipher aesCipher = Cipher.getInstance("AES");

		aesCipher.init(Cipher.ENCRYPT_MODE, aesKeySpec);

		byte[] encryptedContent = aesCipher.doFinal(data);

		String encrypted = Utils.bytes2HexString(encryptedContent);

		_logger.info("encrypted message:");
		_logger.info(encrypted);

		return encryptedContent;
	}

	/**
	 * Decrypt given cipher text
	 * 
	 * @param cipherText
	 * @return
	 * @throws Exception
	 */
	public byte[] decipher(byte[] cipherText) throws Exception
	{
		SecretKeySpec aesKeySpec = new SecretKeySpec(secretKey, "AES");

		Cipher aesCipher = Cipher.getInstance("AES");

		aesCipher.init(Cipher.DECRYPT_MODE, aesKeySpec);

		byte[] decryptedContent = aesCipher.doFinal(cipherText);

		String decrypted = Utils.bytes2HexString(decryptedContent);

		_logger.info("decrypted message:");
		_logger.info(decrypted);

		return decryptedContent;
	}

}
