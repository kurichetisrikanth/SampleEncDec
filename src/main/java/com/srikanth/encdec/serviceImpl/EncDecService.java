package com.srikanth.encdec.serviceImpl;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
//import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import com.srikanth.encdec.controller.OCSReqResDTO;
import com.srikanth.encdec.util.SignEnc;
import com.srikanth.encdec.util.VerifyDec;

@Component
public class EncDecService {
	
	public OCSReqResDTO getOCSReqRes(String request){
		OCSReqResDTO dto = null;
		try {
			SignedJWT signedJWT = SignEnc.signing(request);
			JWEObject jweObject = SignEnc.encrypt(signedJWT);
			dto = getOCSReqResFormat(jweObject);
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		return dto;
		
	}
	

	public OCSReqResDTO getOCSReqResFormat(JWEObject jweObject ){
		OCSReqResDTO req_res_dto = new OCSReqResDTO();
		String headers = jweObject.serialize();
		req_res_dto.setHeaders(headers.substring(0, headers.indexOf('.')));
		req_res_dto.setEncrypted_key(jweObject.getEncryptedKey().toString());
		req_res_dto.setCiphertext(jweObject.getCipherText().toString());
		req_res_dto.setIv(jweObject.getIV().toString());
		req_res_dto.setTag(jweObject.getAuthTag().toString());
		
		return req_res_dto;
		
	}
	
	public String processOCSRequest(OCSReqResDTO req) {
		String subject = "";
		SignedJWT signedJWT;
		try {
			signedJWT = VerifyDec.decrypt_verify(req.toString());
			JWTClaimsSet obj = JWTClaimsSet.parse(signedJWT.getPayload().toJSONObject());
			
			if(signedJWT != null) {
				subject = signedJWT.getJWTClaimsSet().getSubject();
				
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return subject;
	}

}