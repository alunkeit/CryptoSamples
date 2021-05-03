/**
 * Only for demonstration purposes
 */
package de.fom.samples;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author alunkeit
 *
 */
public class TLSClient
{

	public void createConnection()
	{
		try
		{
			SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();

			SSLSocket socket = (SSLSocket) factory.createSocket("www.google.com", 443);

			String suites[] = { "TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256" };

			socket.setEnabledCipherSuites(suites);

			String ciphers[] = socket.getEnabledCipherSuites();
			String protocols[] = socket.getEnabledProtocols();

			for (String s : ciphers)
				System.out.println(s);

			for (String p : protocols)
				System.out.println(p);

			socket.startHandshake();

		}
		catch (Exception e)
		{
			e.printStackTrace();
		}

	}

	public static void main(String args[])
	{
		System.setProperty("javax.net.debug", "all");

		new TLSClient().createConnection();
	}

}
