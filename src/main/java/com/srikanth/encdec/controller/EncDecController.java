package com.srikanth.encdec.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.srikanth.encdec.model.OCSReqResDTO;
import com.srikanth.encdec.serviceImpl.EncDecService;

@RestController
public class EncDecController {
	
	@Autowired
	private EncDecService service;
	
	@PostMapping("/sender-request")
	public OCSReqResDTO sendRequest(@RequestBody String req) {
		return service.getOCSReqRes(req);
	}
	
	@PostMapping(value="/rec-process-request")
	public String recRequest(@RequestBody OCSReqResDTO req) {
		return service.processOCSRequest(req);
	}
	
	@PostMapping(value="/rec-request")
	public OCSReqResDTO receiverRequest(@RequestBody String req) {
		return service.getMWRequest(req);
	}
	
	@PostMapping(value="/sender-process-response")
	public String processMWResponse(@RequestBody OCSReqResDTO req) {
		return service.processMWResponse(req);
	}
}
