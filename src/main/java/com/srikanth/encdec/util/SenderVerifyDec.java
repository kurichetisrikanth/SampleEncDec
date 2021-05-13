package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

public class SenderVerifyDec {

	public static SignedJWT decrypt_verify(String jweString) throws JOSEException {
		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.sender_publicKey).privateKey((RSAPrivateKey) LoadKeys.sender_privateKey)
				.build();

		SignedJWT signedJWT = null;
		try {
			JWEObject jweObject = JWEObject.parse(jweString);
			jweObject.decrypt(new RSADecrypter(jwk));
			signedJWT = jweObject.getPayload().toSignedJWT();
			if(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) LoadKeys.rec_publicKey))) 
				return signedJWT;
				
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return signedJWT;
	}

}
