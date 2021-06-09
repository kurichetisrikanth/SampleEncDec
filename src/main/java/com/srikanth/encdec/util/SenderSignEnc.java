package com.srikanth.encdec.util;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

public class SenderSignEnc {

	public static JWSObject signing(String payload) throws JOSEException {
		RSAKey jwk = new RSAKey.Builder((RSAPublicKey) LoadKeys.sender_publicKey).privateKey((RSAPrivateKey) LoadKeys.sender_privateKey).build();
		JWSSigner signer = new RSASSASigner(jwk);
		Payload pl = new Payload(payload);
		JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS512).build();
		JWSObject jwsObject = new JWSObject(header, pl);
		jwsObject.sign(signer);
		return jwsObject;
	}
	public static JWEObject encrypt(JWSObject jwsObject) throws JOSEException {
		JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256CBC_HS512).build();
		JWEObject jweObject = new JWEObject(header, new Payload(jwsObject));
		jweObject.encrypt(new RSAEncrypter((RSAPublicKey) LoadKeys.rec_publicKey));
		return jweObject;
	}
}
