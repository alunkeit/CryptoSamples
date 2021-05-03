/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import java.io.FileOutputStream;
import java.io.IOException;

/**
 * 
 * @author alunkeit
 *
 */
public class Utils
{

	/**
	 * Convert a byte to hex representation
	 */
	public static String byte2Hex(byte b)
	{
		char[] hex = new char[2];
		hex[0] = Character.forDigit((b >> 4) & 0xF, 16);
		hex[1] = Character.forDigit((b & 0xF), 16);

		return new String(hex);
	}

	/**
	 * Convert bytes to hex string
	 * 
	 * @param bytes
	 * @return
	 */
	public static String bytes2HexString(byte[] bytes)
	{
		StringBuffer hexBuffer = new StringBuffer();

		for (int i = 0; i < bytes.length; i++)
			hexBuffer.append(byte2Hex(bytes[i]));

		return hexBuffer.toString();
	}

	/**
	 * Convert character to number
	 * 
	 * @param hexChar
	 * @return
	 */
	private static int char2Digit(char hexChar)
	{
		int num = Character.digit(hexChar, 16);

		if (num == -1)
			throw new IllegalArgumentException("not a hex char: " + hexChar);

		return num;
	}

	/**
	 * Convert hex rencoding to byte
	 * 
	 * @param hexString
	 * @return
	 */
	public static byte hex2Byte(String hexString)
	{
		int first = char2Digit(hexString.charAt(0));
		int second = char2Digit(hexString.charAt(1));

		return (byte) ((first << 4) + second);
	}

	/**
	 * Convert hex string to byte array
	 * 
	 * @param s
	 * @return
	 */
	public static byte[] hex2Bytes(String s)
	{
		if (s.length() % 2 == 1)
			throw new IllegalArgumentException("hex string cannot be odd");

		byte[] baBytes = new byte[s.length() / 2];

		for (int i = 0; i < s.length(); i += 2)
			baBytes[i / 2] = hex2Byte(s.substring(i, i + 2));

		return baBytes;
	}

	/**
	 * Write to a given file
	 * 
	 * @param fileName
	 * @param data
	 * @throws IOException
	 */
	public static void write2File(String fileName, byte[] data) throws IOException
	{
		try (FileOutputStream out = new FileOutputStream(fileName))
		{
			out.write(data);
		}
	}
}
