/**
 * 
 */
package de.fom.samples;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.SecretKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

/**
 * @author alunkeit
 *
 */
public class CustomKeyStore
{

	private KeyStore store;

	private String type;

	/**
	 * 
	 */
	public CustomKeyStore(String type)
	{
		this.type = type;
	}

	/**
	 * Open an already existing key store
	 * 
	 * @param fileName
	 * @param passphrase
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 * @throws FileNotFoundException
	 * @throws IOException
	 * @throws KeyStoreException
	 */
	public void open(InputStream in, char[] passphrase)
			throws NoSuchAlgorithmException, CertificateException, FileNotFoundException, IOException, KeyStoreException
	{
		store = KeyStore.getInstance(type);
		store.load(in, passphrase);
	}

	/**
	 * Create a new key store
	 * 
	 * @param format
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws KeyStoreException
	 */
	public void create() throws NoSuchAlgorithmException, IOException, CertificateException, KeyStoreException
	{
		store = KeyStore.getInstance(type);

		store.load(null);
	}

	public void store(KeyStore store)
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		try (FileOutputStream out = new FileOutputStream("keystore.p12"))
		{
			store.store(out, "keystorepassphrase".toCharArray());
		}
	}

	public void addSecretKey(SecretKey key, String alias, char[] passphrase)
			throws NoSuchAlgorithmException, KeyStoreException
	{

		SecretKeyEntry entry = new SecretKeyEntry(key);

		PasswordProtection prot = new PasswordProtection(passphrase);

		store.setEntry(alias, entry, prot);
	}

	public Key getKey(String alias, char[] passphrase)
			throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException
	{
		return store.getKey(alias, passphrase);
	}

	public void save(OutputStream out, char passphrase[])
			throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
	{
		store.store(out, passphrase);
	}

	/**
	 * @param args
	 */
	public static void main(String[] args)
	{
		try
		{
			CustomKeyStore kStore = new CustomKeyStore("PKCS12");

			kStore.create();

			SecretKey k = KeyGenerator.getInstance("AES").generateKey();

			kStore.addSecretKey(k, "MySecretKey", "topsecret".toCharArray());

			try (var out = new FileOutputStream("keystore.p12"))
			{
				kStore.save(out, "secret".toCharArray());
			}

			kStore = null;

			kStore = new CustomKeyStore("PKCS12");

			try (var in = new FileInputStream("keystore.p12"))
			{
				kStore.open(in, "secret".toCharArray());

				Key k2 = kStore.getKey("MySecretKey", "topsecret".toCharArray());

				System.out.println(Utils.bytes2HexString(k.getEncoded()));
				System.out.println(Utils.bytes2HexString(k2.getEncoded()));

				if (k.getEncoded().equals(k2.getEncoded()))
				{
					System.out.println("Keys are identical!");
				}
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

	}

}
