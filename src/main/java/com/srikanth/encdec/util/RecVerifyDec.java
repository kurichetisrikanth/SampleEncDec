package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;

public class RecVerifyDec {

	public static String decrypt_verify(String jweString) {
		String plainText = "";
		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.rec_publicKey).privateKey((RSAPrivateKey) LoadKeys.rec_privateKey).build();
		try {
			JWEObject jweObject = JWEObject.parse(jweString);
			jweObject.decrypt(new RSADecrypter(jwk));
			JWSObject jwsObject = jweObject.getPayload().toJWSObject();
			if(jwsObject.verify(new RSASSAVerifier((RSAPublicKey) LoadKeys.sender_publicKey))) {
				plainText = jwsObject.getPayload().toString();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return plainText;
	}
}
