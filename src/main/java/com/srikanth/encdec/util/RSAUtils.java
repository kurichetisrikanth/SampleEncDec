package com.srikanth.encdec.util;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class RSAUtils {
	
	private RSAUtils() {
		throw new IllegalStateException("utility class");
	}
	
	private static PublicKey sender_publicKey;
	private static PrivateKey sender_privateKey;
	private static PublicKey rec_publicKey;
	private static PrivateKey rec_privateKey;
	
	public static void generateKeys() throws NoSuchAlgorithmException {
		final KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		
		final KeyPair sender_pair = keyGen.generateKeyPair();
		sender_publicKey = sender_pair.getPublic();
		sender_privateKey = sender_pair.getPrivate();
		
		final KeyPair rec_pair = keyGen.generateKeyPair();
		rec_publicKey = rec_pair.getPublic();
		rec_privateKey = rec_pair.getPrivate();
		
	}
	public static PublicKey getSenderPublicKey() {
		return sender_publicKey;
	}
	
	public static PrivateKey getSenderPrivateKey() {
		return sender_privateKey;
	}
	public static PublicKey getRecPublicKey() {
		return rec_publicKey;
	}
	
	public static PrivateKey getRecPrivateKey() {
		return rec_privateKey;
	}
}
