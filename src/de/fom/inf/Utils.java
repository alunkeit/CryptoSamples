package de.fom.inf;

public class Utils {

	public static String byte2Hex(byte b) {
		char[] hex = new char[2];
		hex[0] = Character.forDigit((b >> 4) & 0xF, 16);
		hex[1] = Character.forDigit((b & 0xF), 16);
		return new String(hex);
	}

	public static String bytes2HexString(byte[] bytes) {
		StringBuffer hexBuffer = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			hexBuffer.append(byte2Hex(bytes[i]));
		}
		return hexBuffer.toString();
	}

	private static int toDigit(char hexChar) {
		int digit = Character.digit(hexChar, 16);
		if (digit == -1) {
			throw new IllegalArgumentException("Invalid Hexadecimal Character: " + hexChar);
		}
		return digit;
	}

	public static byte hex2Byte(String hexString) {
		int firstDigit = toDigit(hexString.charAt(0));
		int secondDigit = toDigit(hexString.charAt(1));
		return (byte) ((firstDigit << 4) + secondDigit);
	}

	public static byte[] hex2Bytes(String hexString) {
		if (hexString.length() % 2 == 1) {
			throw new IllegalArgumentException("hex string cannot be odd");
		}

		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < hexString.length(); i += 2) {
			bytes[i / 2] = hex2Byte(hexString.substring(i, i + 2));
		}
		return bytes;
	}
}
