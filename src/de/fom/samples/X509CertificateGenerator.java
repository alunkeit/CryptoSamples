/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * 
 * @author alunkeit
 *
 */
public class X509CertificateGenerator
{

	private static long ONE_DAY = 1000L * 60 * 60 * 24;

	Logger _logger = Logger.getLogger(X509CertificateGenerator.class.toString());

	/**
	 * Generates an RSA key pair
	 * 
	 * @param keySize - The length of the key to be generated in bits
	 * @return - A KeyPair
	 * @throws NoSuchAlgorithmException
	 * @throws GeneralSecurityException
	 */
	public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, GeneralSecurityException
	{
		/*
		 * a BigInteger for the exponent, a SecureRandom type object, the strength of the key, and the number of
		 * iterations to the algorithm that verifies the generation of the keys based off prime numbers. 80 is more than
		 * enough
		 */
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BCFIPS");

		kpGen.initialize(keySize);

		KeyPair kp = kpGen.generateKeyPair();

		return kp;
	}

	/**
	 * Generates a new root certificate
	 * 
	 * @param kp             - The key pair of the certificate
	 * @param principal      - The principal name
	 * @param validityPeriod - The validity period in days from now
	 * @return
	 * @throws CertIOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws OperatorCreationException
	 */
	public X509Certificate generateRootCertificate(KeyPair kp, String principal, int validityPeriod)
			throws CertIOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException
	{

		long time = System.currentTimeMillis();

		X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(new X500Name("CN=" + principal), // issuer
				BigInteger.valueOf(System.currentTimeMillis()) // serial number
						.multiply(BigInteger.valueOf(10)),
				new Date(time - 1000L * 5), // start time
				new Date(time + validityPeriod * ONE_DAY), // expiry time
				new X500Name("CN=" + principal), // subject
				kp.getPublic()); // subject public key

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

		v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false,
				extUtils.createSubjectKeyIdentifier(kp.getPublic()));

		v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false,
				extUtils.createAuthorityKeyIdentifier(kp.getPublic()));

		v3CertBldr.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

		v3CertBldr.addExtension(Extension.basicConstraints, true, new BasicConstraints(2));

		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BCFIPS");

		return new JcaX509CertificateConverter().setProvider("BCFIPS")
				.getCertificate(v3CertBldr.build(signerBuilder.build(kp.getPrivate())));
	}

	/**
	 * Generates an End Entity certificate
	 * 
	 * @param ca             - The issuer of the certificate
	 * @param caPrivKey      - The private key of the certificate issuer
	 * @param pub            - The public key of the certificate
	 * @param subject        - The subject of the certificate
	 * @param validityPeriod - The validity period of the certificate in days from now
	 * @return
	 * @throws IOException
	 * @throws GeneralSecurityException
	 * @throws OperatorException
	 */
	public X509Certificate generateV3EndEntity(X509Certificate ca, PrivateKey caPrivKey, PublicKey pub, String subject,
			long validityPeriod) throws IOException, GeneralSecurityException, OperatorException
	{
		_logger.fine("Generating End entity certificate");

		long time = System.currentTimeMillis();

		X509v3CertificateBuilder v3CertBldr = new JcaX509v3CertificateBuilder(ca.getSubjectX500Principal(), // issuer
				BigInteger.valueOf(System.currentTimeMillis()) // serial number
						.multiply(BigInteger.valueOf(10)),
				new Date(time - 1000L * 5), // start time
				new Date(time + validityPeriod * ONE_DAY), // expiry time
				new X500Principal("CN=" + subject), // subject
				pub); // subject public key

		_logger.fine("adding extensions");

		JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
		v3CertBldr.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(pub));

		v3CertBldr.addExtension(Extension.authorityKeyIdentifier, false,
				extUtils.createAuthorityKeyIdentifier(ca.getPublicKey()));

		v3CertBldr.addExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

		v3CertBldr.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

		_logger.fine("Finished adding extensions");

		JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BCFIPS");

		_logger.fine("now signing the certificate template");

		return new JcaX509CertificateConverter().setProvider("BCFIPS")
				.getCertificate(v3CertBldr.build(signerBuilder.build(caPrivKey)));

	}
}
