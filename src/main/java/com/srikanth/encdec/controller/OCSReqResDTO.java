package com.srikanth.encdec.controller;

public class OCSReqResDTO {
	
	private String headers;
	private String encrypted_key;
	private String ciphertext;
	private String iv;
	private String tag;
	
	public String getHeaders() {
		return headers;
	}
	public void setHeaders(String headers) {
		this.headers = headers;
	}
	public String getEncrypted_key() {
		return encrypted_key;
	}
	public void setEncrypted_key(String encrypted_key) {
		this.encrypted_key = encrypted_key;
	}
	public String getCiphertext() {
		return ciphertext;
	}
	public void setCiphertext(String ciphertext) {
		this.ciphertext = ciphertext;
	}
	public String getIv() {
		return iv;
	}
	public void setIv(String iv) {
		this.iv = iv;
	}
	public String getTag() {
		return tag;
	}
	public void setTag(String tag) {
		this.tag = tag;
	}
	
	
	@Override
	public String toString() {
		return headers +"."+ encrypted_key +"."+ iv +"."+ ciphertext +"."+ tag;
	}
	

}
