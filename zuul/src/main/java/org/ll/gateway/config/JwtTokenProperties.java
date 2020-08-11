package org.ll.gateway.config;

import lombok.Data;

@Data
public class JwtTokenProperties {
	
	private KeystoreProperties signer;
	private KeystoreProperties verifier;
	
}
