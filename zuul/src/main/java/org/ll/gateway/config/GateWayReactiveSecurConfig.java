//package org.ll.gateway.config;
//
//import java.io.IOException;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.NoSuchAlgorithmException;
//import java.security.cert.CertificateException;
//import java.security.interfaces.RSAPublicKey;
//
//import org.bouncycastle.util.encoders.Hex;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
//import org.springframework.boot.context.properties.ConfigurationProperties;
//import org.springframework.context.annotation.Bean;
//import org.springframework.core.io.ClassPathResource;
//import org.springframework.security.authorization.AuthorizationDecision;
//import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
//import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
//import org.springframework.security.config.web.server.ServerHttpSecurity;
//import org.springframework.security.core.context.ReactiveSecurityContextHolder;
//import org.springframework.security.core.context.SecurityContext;
//import org.springframework.security.web.server.SecurityWebFilterChain;
//import org.springframework.web.server.WebFilter;
//
//@EnableWebFluxSecurity
//public class GateWayReactiveSecurConfig  {
//
//	private final static Logger log = LoggerFactory.getLogger(GateWayReactiveSecurConfig.class);
//
//	@Bean
//	@ConfigurationProperties("cloudms.security.token.jwt")
//	public JwtTokenProperties jwtTokenProperties(){
//		return new JwtTokenProperties();
//	}
//	
//	@Bean
//	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) throws Exception {
//		log.debug("init springSecurityFilterChain");
//		
//		http
//			.authorizeExchange()
//				.pathMatchers("/actuator/**").permitAll()
//				.pathMatchers("/v1/api/me").hasAuthority("SCOPE_message:read")
//				.pathMatchers("/v1/api/menus").hasAuthority("SCOPE_message:read")
////				.pathMatchers("/v1/api/**").hasRole("USER")
//				.anyExchange().authenticated()
//			.and()
//			.addFilterAt(filter, SecurityWebFiltersOrder.AUTHENTICATION)
//			.oauth2ResourceServer()
//				.jwt()
//				.publicKey(publicKey())
//				;
//		return http.build();
//	}
//	
//	WebFilter filter = (exchange, chain) -> {
//				ReactiveSecurityContextHolder.getContext()
//				.filter(c -> {
//					log.debug("c.getAuthentication(): [{}]", c.getAuthentication());
//					return c.getAuthentication() != null;
//				})
//				;
//				return chain.filter(exchange);
//	};
//	
//	
//	public RSAPublicKey publicKey(){
//		log.debug("init public key");
//		try {
//			KeystoreProperties verifier = jwtTokenProperties().getVerifier();
//			KeyStore keystore = KeyStore.getInstance(verifier.getKeyStoreType());
//			keystore.load(new ClassPathResource(verifier.getKeyStore()).getInputStream(), verifier.getKeyStorePwd().toCharArray());
//			RSAPublicKey key = (RSAPublicKey)keystore.getCertificate(verifier.getKeyAlias()).getPublicKey();
//			log.debug("key.getEncoded(): [{}]", Hex.toHexString(key.getEncoded()));
//			return key;
//		} catch (KeyStoreException
//				| NoSuchAlgorithmException | CertificateException | IOException e) {
//			log.error("fail to get public key", e);
//		}
//		return null;
//	}
//	
//}
