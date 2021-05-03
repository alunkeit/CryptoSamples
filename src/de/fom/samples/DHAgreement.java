/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

import org.apache.log4j.Logger;

/**
 * @author alunk
 * 
 *         This class demonstrates the DH key agreement
 */
public class DHAgreement
{

	private static final String dhG14 = "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
			+ "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
			+ "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
			+ "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
			+ "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
			+ "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
			+ "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
			+ "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
			+ "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
			+ "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510" + "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF";

	private DHParameterSpec spec;

	private KeyPair kp;

	private static Logger _logger = Logger.getLogger(DHAgreement.class);

	public DHAgreement()
	{

	}

	/**
	 * Generates a parameter specification for DH
	 * 
	 * @return
	 * @throws GeneralSecurityException
	 * @throws IOException
	 */
	public void generateParameters(int strength) throws GeneralSecurityException, IOException
	{

		AlgorithmParameterGenerator algGen = AlgorithmParameterGenerator.getInstance("DH", "BCFIPS");

		algGen.init(strength);

		AlgorithmParameters dsaParams = algGen.generateParameters();

		byte baParams[] = dsaParams.getEncoded();

		System.out.println("DH-Parameter: " + Utils.bytes2HexString(baParams));

		spec = dsaParams.getParameterSpec(DHParameterSpec.class);

		_logger.info("Modulus P: " + spec.getP());
		_logger.info("Generator G: " + spec.getG());
	}

	/**
	 * This function demonstrates how to construct the DH parameter spec from a given specification. This implementation
	 * makes use of DH goup 14 as specified in RFC 3526
	 * 
	 * @return
	 */
	public void generateG14Spec()
	{

		BigInteger modulus = new BigInteger(dhG14.replaceAll("\\s", ""), 16);
		BigInteger generator = BigInteger.TWO;

		spec = new DHParameterSpec(modulus, generator);

		_logger.info("Modulus P: " + spec.getP());
		_logger.info("Generator G: " + spec.getG());
	}

	/**
	 * Generates a key pair. Used by Alice and Bob for further processing
	 * 
	 * @param dhParameterSpec
	 * @return
	 * @throws GeneralSecurityException
	 */
	public void generateKeyPair() throws GeneralSecurityException
	{
		KeyPairGenerator keyPair = KeyPairGenerator.getInstance("DH", "BCFIPS");

		keyPair.initialize(spec);

		kp = keyPair.generateKeyPair();
	}

	/**
	 * Does the key agreement. Used by Alice and Bob.
	 * 
	 * @param initiatorPrivate - The private key used in the computation of the shared secret
	 * @param recipientPublic
	 * @return
	 * @throws GeneralSecurityException
	 */
	public byte[] computeSharedSecret(PublicKey recipientPublic) throws GeneralSecurityException
	{
		KeyAgreement agreement = KeyAgreement.getInstance("DH", "BCFIPS");

		agreement.init(kp.getPrivate());

		agreement.doPhase(recipientPublic, true);

		SecretKey agreedKey = agreement.generateSecret("AES[256]");

		return agreedKey.getEncoded();
	}

	/**
	 * Returns the public key for the use with DH
	 * 
	 * @return
	 */
	public PublicKey getPublic()
	{
		return kp.getPublic();
	}

}
