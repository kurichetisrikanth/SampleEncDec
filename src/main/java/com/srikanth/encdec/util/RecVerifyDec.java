package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

public class RecVerifyDec {

	public static SignedJWT decrypt_verify(String jweString) {
		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.rec_publicKey).privateKey((RSAPrivateKey) LoadKeys.rec_privateKey)
				.build();
		SignedJWT signedJWT = null;
		try {
			JWEObject jweObject = JWEObject.parse(jweString);
			jweObject.decrypt(new RSADecrypter(jwk));
			signedJWT = jweObject.getPayload().toSignedJWT();
			if(signedJWT.verify(new RSASSAVerifier((RSAPublicKey) LoadKeys.sender_publicKey))) 
				return signedJWT;
				
		} catch (Exception e) {
			e.printStackTrace();
		}
		return signedJWT;
	}

}
