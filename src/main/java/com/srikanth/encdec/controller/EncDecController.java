package com.srikanth.encdec.controller;

import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.srikanth.encdec.model.OCSReqResDTO;
import com.srikanth.encdec.serviceImpl.EncDecService;
import com.srikanth.encdec.util.RSAUtils;

@RestController
public class EncDecController {
	
	@Autowired
	private EncDecService service;
	
	
	//IB REQUEST
	@PostMapping("/sender-request")
	public OCSReqResDTO sendRequest(@RequestBody String req) {
		return service.getOCSReqRes(req);
	}
	
	//MW REQUEST PROCESS
	@PostMapping(value="/rec-process-request")
	public String processRequest(@RequestBody OCSReqResDTO req) {
		return service.processOCSRequest(req);
	}
	
	
	//MW RESPONSE SENDING
	@PostMapping(value="/rec-request")
	public OCSReqResDTO receiverRequest(@RequestBody String req) {
		return service.getMWRequest(req);
	}
	
	//IB RESPONSE PROCESS
	@PostMapping(value="/sender-process-response")
	public String processResponse(@RequestBody OCSReqResDTO req) {
		return service.processMWResponse(req);
	}
	
	@EventListener(ApplicationReadyEvent.class)
	public void generateRSAKeys() {
		try {
			RSAUtils.generateKeys();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
}
