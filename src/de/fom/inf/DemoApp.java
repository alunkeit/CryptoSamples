/**
 * 
 */
package de.fom.inf;

import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509Certificate;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * @author alunk
 *
 */
public class DemoApp
{

	public static byte[] demonstrateDH() throws Exception
	{
		DHAgreement alice = new DHAgreement();
		DHAgreement bob = new DHAgreement();

		// DHParameterSpec parameterSpec = generateParameters();
		alice.generateG14Spec();
		bob.generateG14Spec();

		alice.generateKeyPair();
		bob.generateKeyPair();

		byte aliceShared[] = alice.computeSharedSecret(bob.getPublic());
		byte bobShared[] = bob.computeSharedSecret(alice.getPublic());

		System.out.println("Alice computes\n: " + Utils.bytes2HexString(aliceShared));
		System.out.println("Bob computes\n: " + Utils.bytes2HexString(bobShared));

		if (!java.util.Arrays.equals(aliceShared, bobShared))
			throw new Exception("an error occured during key computation");

		return aliceShared;

	}

	public static void demonstrateAES() throws Exception
	{

		byte[] secret = demonstrateDH();

		RawAESEncryptor encryptor = new RawAESEncryptor(secret);

		String msg = "Hello World, what an interesting lesson!";

		byte[] cipher = encryptor.encipher(msg.getBytes());

		System.out.println("Cipher:\n" + Utils.bytes2HexString(cipher));

		byte[] message = encryptor.decipher(cipher);

		String deciphered = new String(message);

		System.out.println("Deciphered: " + deciphered);

		if (!deciphered.equals(msg))
			throw new Exception("clear text does not match to message");
	}

	public static void demonstrateCertGeneration()
	{
		try
		{
			X509CertificateGenerator certGen = new X509CertificateGenerator();

			KeyPair kp = certGen.generateRSAKeyPair(2048);

			X509Certificate cert = certGen.generateSelfSignedRoot(kp, "Demonstration CA", 365);

			System.out.println(cert.toString());
		} catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args)
	{

		try
		{
			Security.addProvider(new BouncyCastleFipsProvider());

			DemoApp.demonstrateDH();

			DemoApp.demonstrateAES();

			DemoApp.demonstrateCertGeneration();

		} catch (Exception e)
		{
			e.printStackTrace();
		}

	}

}
