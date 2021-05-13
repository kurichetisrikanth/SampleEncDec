package com.srikanth.encdec.util;

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class LoadKeys {
	public static PrivateKey sender_privateKey;
	public static PublicKey rec_publicKey;
	public static PrivateKey rec_privateKey;
	public static PublicKey sender_publicKey;

	static {
		ClassLoader classLoader = ReceiverSignEnc.class.getClassLoader();

		File sender_pri_key_file = new File(classLoader.getResource("static/sender_pri_key.pem").getFile());
		File rec_pub_key_file = new File(classLoader.getResource("static/rec_pub_key.pem").getFile());
		File rec_pri_key_file = new File(classLoader.getResource("static/rec_pri_key.pem").getFile());
		File sender_pub_key_file = new File(classLoader.getResource("static/sender_pub_key.pem").getFile());

		try {
			rec_publicKey = readPublicKey(rec_pub_key_file);
			sender_privateKey = readPrivateKey(sender_pri_key_file);
			rec_privateKey = readPrivateKey(rec_pri_key_file);
			sender_publicKey = readPublicKey(sender_pub_key_file);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	public static RSAPublicKey readPublicKey(File file) throws Exception {
		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

		String publicKeyPEM = key.replace("-----BEGIN PUBLIC KEY-----", "").replaceAll(System.lineSeparator(), "")
				.replace("-----END PUBLIC KEY-----", "");

		byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64(publicKeyPEM);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
		return (RSAPublicKey) keyFactory.generatePublic(keySpec);
	}

	public static RSAPrivateKey readPrivateKey(File file) throws Exception {
		String key = new String(Files.readAllBytes(file.toPath()), Charset.defaultCharset());

		String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "").replaceAll(System.lineSeparator(), "")
				.replace("-----END PRIVATE KEY-----", "");

		byte[] encoded = org.apache.commons.codec.binary.Base64.decodeBase64(privateKeyPEM);

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
	}
}
