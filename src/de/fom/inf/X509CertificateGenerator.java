package de.fom.inf;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class X509CertificateGenerator {

	private static long ONE_DAY = 1000L * 60 * 60 * 24;

	public KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, GeneralSecurityException {
		/*
		 * a BigInteger for the exponent, a SecureRandom type object, the strength of
		 * the key, and the number of iterations to the algorithm that verifies the
		 * generation of the keys based off prime numbers. 80 is more than enough
		 */
		KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BCFIPS");

		kpGen.initialize(keySize);

		KeyPair kp = kpGen.generateKeyPair();

		AsymmetricRSAPublicKey rsaPubKey = new AsymmetricRSAPublicKey(FipsRSA.ALGORITHM, kp.getPublic().getEncoded());

		AsymmetricRSAPrivateKey rsaPrivKey = new AsymmetricRSAPrivateKey(FipsRSA.ALGORITHM,
				kp.getPrivate().getEncoded());

		return kp;
	}

	public X509Certificate generateSelfSignedRoot(KeyPair kp, String principal, int validityPeriod)
			throws CertIOException, NoSuchAlgorithmException, CertificateException, OperatorCreationException {

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
}
