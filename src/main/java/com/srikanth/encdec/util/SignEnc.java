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

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SignEnc {

	private static SignedJWT signedJWT = null;

	private static PrivateKey sender_privateKey;
	private static PublicKey rec_publicKey;
	private static PrivateKey rec_privateKey;
	private static PublicKey sender_publicKey;

	static {
		ClassLoader classLoader = SignEnc.class.getClassLoader();

		File sender_pri_key_file = new File(classLoader.getResource("static/sender_pri_key.pem").getFile());
		File rec_pub_key_file = new File(classLoader.getResource("static/rec_pub_key.pem").getFile());

		File sender_pub_key_file = new File(classLoader.getResource("static/sender_pub_key.pem").getFile());

		try {
			rec_publicKey = readPublicKey(rec_pub_key_file);
			sender_privateKey = readPrivateKey(sender_pri_key_file);

			sender_publicKey = readPublicKey(sender_pub_key_file);
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public static SignedJWT signing(String payload) throws JOSEException {

		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) sender_publicKey).privateKey((RSAPrivateKey) sender_privateKey)
				.build();

		JWSSigner signer = new RSASSASigner(jwk);

		JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
				.subject("sender subject")
				.issuer("sender")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();

		String jsonStr = "{\n"
				+ "    \"inquiryType\":\"GI\",\n"
				+ "    \"globalId\":\"1002345678899\",\n"
				+ "    \"functionalId\":\"ACCOUNTSUM\",\n"
				+ "    \"unidId\":[\"PRD\", \"OMN\"]\n"
				+ "}";
		try {
			JSONObject json = (JSONObject) JSONObjectUtils.parse(jsonStr);
		} catch (ParseException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS512).keyID(jwk.getKeyID()).build(), claimsSet);

		signedJWT.sign(signer);

		System.out.println("signing status is:::::::"+signedJWT.getState());
		
		return signedJWT;

	}

	public static JWEObject encrypt(SignedJWT signedJWT) throws JOSEException {
		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512_DEPRECATED)
						.contentType("JWT") // required to indicate nested JWT
						.build(),
				new Payload(signedJWT));

		// Encrypt with the recipient's public key
		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) rec_publicKey));

		// Serialise to JWE compact form
		String jweString = jweObject.serialize();

		System.out.println("encryptedKey::::::::" + jweObject.getEncryptedKey());
		System.out.println("ciphertext::::::::" + jweObject.getCipherText());
		System.out.println("iv::::::::" + jweObject.getIV());
		System.out.println("tag::::::::" + jweObject.getAuthTag());
		System.out.println("payload::::::::" + jweObject.getPayload());
		System.out.println("header::::::::" + Base64.encode(jweObject.getHeader().toString()));
		System.out.println("jweString::::::::" + jweString);

		return jweObject;
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
