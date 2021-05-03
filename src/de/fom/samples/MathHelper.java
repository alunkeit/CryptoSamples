/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import java.math.BigInteger;

/**
 * 
 * @author alunkeit
 *
 */
public class MathHelper
{

	public static void decryptionExample()
	{
		BigInteger i = new BigInteger("90");

		BigInteger pow = i.pow(147);

		System.out.println(pow);

		BigInteger m = pow.mod(new BigInteger("253"));

		System.out.println(m);

	}

	public static void signatureExample()
	{
		BigInteger m = new BigInteger("7");
		BigInteger d = new BigInteger("147");
		BigInteger e = new BigInteger("3");
		BigInteger n = new BigInteger("253");

		BigInteger s = (m.pow(d.intValue())).mod(n);

		System.out.println("signature value: " + s);

		BigInteger v = (s.pow(e.intValue())).mod(n);

		System.out.println("message: " + m);
	}

	public static void main(String[] args)
	{

		MathHelper.decryptionExample();

		MathHelper.signatureExample();

	}

}
