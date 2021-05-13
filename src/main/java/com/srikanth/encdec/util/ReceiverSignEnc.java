package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
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
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class ReceiverSignEnc {

	private static SignedJWT signedJWT = null;

	
	public static SignedJWT signing(String payload) throws JOSEException {

		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.rec_publicKey).privateKey((RSAPrivateKey) LoadKeys.rec_privateKey)
				.build();

		JWSSigner signer = new RSASSASigner(jwk);

		JWTClaimsSet claimsSet = null;
		
		try {
			JSONObject json = (JSONObject) JSONObjectUtils.parse(payload);
			claimsSet = new JWTClaimsSet.Builder()
					.claim("reqBody", json)
					.subject("sender subject")
					.issuer("sender")
					.expirationTime(new Date(new Date().getTime() + 60 * 1000)).build();
		} catch (ParseException e) {
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
						.contentType("JWT") 
						.build(),
				new Payload(signedJWT));

		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) LoadKeys.sender_publicKey));

		return jweObject;
	}


}
