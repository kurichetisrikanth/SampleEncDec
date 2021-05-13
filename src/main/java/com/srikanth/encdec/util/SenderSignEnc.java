package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class SenderSignEnc {

	private static SignedJWT signedJWT = null;
	

	public static SignedJWT signing(String payload) throws JOSEException {

		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.sender_publicKey).privateKey((RSAPrivateKey) LoadKeys.sender_privateKey)
				.build();

		JWSSigner signer = new RSASSASigner(jwk);

		JWTClaimsSet claimsSet = null;
		
		claimsSet = new JWTClaimsSet.Builder()
				.claim("reqBody", payload)
				.subject("sender subject")
				.issuer("sender")
				.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();
		
		signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS512).keyID(jwk.getKeyID()).build(), claimsSet);

		signedJWT.sign(signer);

		System.out.println("signing status is:::::::"+signedJWT.getState());
		
		return signedJWT;

	}
	
	public static JWEObject encrypt(SignedJWT signedJWT) throws JOSEException {
		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512_DEPRECATED)
						.contentType("JWT") 
						.build(),
				new Payload(signedJWT));

		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) LoadKeys.rec_publicKey));

		return jweObject;
	}


}
