/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.apache.log4j.ConsoleAppender;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.PatternLayout;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;

/**
 * @author alunk
 *
 */
public class DemoApp
{

	private static Logger _logger = Logger.getRootLogger();

	static
	{
		_logger.setLevel(Level.DEBUG);

		// Define log pattern layout
		PatternLayout layout = new PatternLayout("%m%n");

		// Add console appender to root logger
		_logger.addAppender(new ConsoleAppender(layout));
	}

	/**
	 * Demonstrates the key agreement between two partners.
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] demonstrateDH() throws Exception
	{
		DHAgreement alice = new DHAgreement();
		DHAgreement bob = new DHAgreement();

		/**
		 * Generate parameters for use with DH group 14
		 */
		alice.generateG14Spec();
		bob.generateG14Spec();

		/**
		 * Generate a pair of private and public key. private key is the exponent, public key is g pow a mod p
		 */

		alice.generateKeyPair();
		bob.generateKeyPair();

		/**
		 * Compute the shared secret
		 */

		byte aliceShared[] = alice.computeSharedSecret(bob.getPublic());
		byte bobShared[] = bob.computeSharedSecret(alice.getPublic());

		_logger.info("Alice computes\n: " + Utils.bytes2HexString(aliceShared));
		_logger.info("Bob computes\n: " + Utils.bytes2HexString(bobShared));

		if (!java.util.Arrays.equals(aliceShared, bobShared))
			throw new Exception("an error occured during key computation");

		return aliceShared;

	}

	/**
	 * Demonstrates the use of AES encryption
	 * 
	 * @throws Exception
	 */
	public static void demonstrateAES() throws Exception
	{

		// compute a shared secret
		byte[] secret = demonstrateDH();

		// create an instance of an encryption algorithm
		RawAESEncryptor encryptor = new RawAESEncryptor(secret);

		String msg = "Hello World, what an interesting lesson!";

		// encrypt a given message
		byte[] cipher = encryptor.encipher(msg.getBytes());

		_logger.info("Cipher:\n" + Utils.bytes2HexString(cipher));

		// decrypt the cipher text
		byte[] message = encryptor.decipher(cipher);

		String deciphered = new String(message);

		_logger.info("Deciphered: " + deciphered);

		if (!deciphered.equals(msg))
			throw new Exception("clear text does not match to message");
	}

	/**
	 * shows how to create self signed certificate using bouncy castle
	 */
	public static void demonstrateCertGeneration()
	{
		try
		{
			// In step 1, a root certificate is generated
			X509CertificateGenerator certGen = new X509CertificateGenerator();

			// Generate a key pair
			KeyPair kpCA = certGen.generateRSAKeyPair(2048);

			// Generate a root certificate
			X509Certificate ca = certGen.generateRootCertificate(kpCA, "Demonstration Root", 365);

			_logger.info(ca.toString());

			Utils.write2File("./root.cer", ca.getEncoded());
			Utils.write2File("./root.key", kpCA.getPrivate().getEncoded());

			// In step 2, a certificate is derived from this CA

			// Generate another key pair
			KeyPair kpClient = certGen.generateRSAKeyPair(2048);

			// Generate a version 3 end entity certificate
			X509Certificate ee = certGen.generateV3EndEntity(ca, kpCA.getPrivate(), kpClient.getPublic(), "hack.me",
					364);

			Utils.write2File("./client.cer", ee.getEncoded());
			Utils.write2File("./client.key", kpClient.getPrivate().getEncoded());

		}
		catch (Exception e)
		{
			e.printStackTrace();
		}
	}

	/**
	 * Shows how to create a digital signature
	 */
	public static void demonstrateDigitalSignature()
	{
		try
		{
			// In step 1, a root certificate is generated
			X509CertificateGenerator certGen = new X509CertificateGenerator();

			KeyPair kp = certGen.generateRSAKeyPair(2048);

			Signature signature = Signature.getInstance("sha256WithRSAEncryption");

			signature.initSign(kp.getPrivate());
			signature.update("Hello World".getBytes());
			byte[] sig = signature.sign();

			String signatureHexString = Utils.bytes2HexString(sig);

			_logger.info("signature length (bytes): " + sig.length);

			_logger.info("readable signature: " + signatureHexString);

			Signature verifier = Signature.getInstance("sha256WithRSAEncryption");

			verifier.initVerify(kp.getPublic());
			verifier.update("Hello World".getBytes());
			boolean verified = verifier.verify(sig);

			_logger.info("signature verified: " + verified);
		}
		catch (GeneralSecurityException e)
		{
			// TODO Auto-generated catch block
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

			DemoApp.demonstrateDigitalSignature();

		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

	}

}
