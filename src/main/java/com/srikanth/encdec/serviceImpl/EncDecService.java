package com.srikanth.encdec.serviceImpl;

import org.springframework.stereotype.Component;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jwt.JWTClaimsSet;
//import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import com.srikanth.encdec.model.OCSReqResDTO;
import com.srikanth.encdec.util.RecVerifyDec;
import com.srikanth.encdec.util.ReceiverSignEnc;
import com.srikanth.encdec.util.SenderSignEnc;
import com.srikanth.encdec.util.SenderVerifyDec;

@Component
public class EncDecService {
	
	public OCSReqResDTO getOCSReqRes(String request){
		OCSReqResDTO dto = null;
		try {
			JWSObject jwsObject = SenderSignEnc.signing(request);
			JWEObject jweObject = SenderSignEnc.encrypt(jwsObject);
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
		return RecVerifyDec.decrypt_verify(req.toString());
	}
	
	public OCSReqResDTO getMWRequest(String request){
		OCSReqResDTO dto = null;
		try {
			JWSObject jwsObject = ReceiverSignEnc.signing(request);
			JWEObject jweObject = ReceiverSignEnc.encrypt(jwsObject);
			dto = getOCSReqResFormat(jweObject);
		} catch (JOSEException e) {
			e.printStackTrace();
		}
		return dto;
		
	}
	public String processMWResponse(OCSReqResDTO req) {
		return SenderVerifyDec.decrypt_verify(req.toString());
	}

}