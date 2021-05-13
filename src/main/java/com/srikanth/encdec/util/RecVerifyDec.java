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
import java.text.ParseException;
import java.util.Date;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class RecVerifyDec {

	private static SignedJWT signedJWT = null;

	private static PublicKey rec_publicKey;
	private static PrivateKey rec_privateKey;
	private static PublicKey sender_publicKey;

	static {
		ClassLoader classLoader = RecVerifyDec.class.getClassLoader();

		File rec_pub_key_file = new File(classLoader.getResource("static/rec_pub_key.pem").getFile());

		File sender_pub_key_file = new File(classLoader.getResource("static/sender_pub_key.pem").getFile());
		File rec_pri_key_file = new File(classLoader.getResource("static/rec_pri_key.pem").getFile());

		try {
			rec_publicKey = readPublicKey(rec_pub_key_file);

			sender_publicKey = readPublicKey(sender_pub_key_file);
			rec_privateKey = readPrivateKey(rec_pri_key_file);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}


	public static SignedJWT decrypt_verify(String jweString) throws JOSEException {
		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) rec_publicKey).privateKey((RSAPrivateKey) rec_privateKey)
				.build();

		boolean isValid = false;
		SignedJWT signedJWT = null;
		//JWEObject jweObject = null;
		try {
			JWEObject jweObject = JWEObject.parse(jweString);
			jweObject.decrypt(new RSADecrypter(jwk));
			signedJWT = jweObject.getPayload().toSignedJWT();
			if(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) sender_publicKey))) 
				return signedJWT;
				
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return signedJWT;
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

	public static void decrypt(String string) {
		
		
	}

}
