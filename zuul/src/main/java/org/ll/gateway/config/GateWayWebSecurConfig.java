package org.ll.gateway.config;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableWebSecurity
public class GateWayWebSecurConfig extends WebSecurityConfigurerAdapter {

	private final static Logger log = LoggerFactory.getLogger(GateWayWebSecurConfig.class);
	
	@Configuration
	@EnableResourceServer
	protected static class ResourceServer extends ResourceServerConfigurerAdapter {

//		@Autowired
//		private ResourceServerTokenServices tokenServices;
		
		@Value("${security.trustStore}")
		private String trustStore;
		
		@Value("${security.storepass}")
		private String storepass;
		
		@Value("${security.trustKeyAlias}")
		private String trustKeyAlias;
		
		@Value("${security.storeType}")
		private String storeType;
		
		@Value("${security.sigAlg}")
		private String sigAlg;
		
		@Value("${security.resourceID}")
		private String API_RESOURCE_ID;
		
		@Override
		public void configure(ResourceServerSecurityConfigurer resources) {
			resources.resourceId(API_RESOURCE_ID).tokenServices(tokenServices()).stateless(false);
		}

		@Override
		public void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				// Since we want the protected resources to be accessible in the UI as well we need 
				// session creation to be allowed (it's disabled by default in 2.0.6)
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
			.and()
				.requestMatchers().antMatchers("/api/**", "/oauth/users/**", "/oauth/clients/**","/me")
			.and()
				.authorizeRequests()
					.antMatchers("/api/**").access(" hasAnyRole('ROLE_API_USER')")
					
					.antMatchers("/me").access("#oauth2.hasScope('read')")					
					.antMatchers("/photos").access("#oauth2.hasScope('read') or (!#oauth2.isOAuth() and hasRole('ROLE_USER'))")                                        
					.antMatchers("/photos/trusted/**").access("#oauth2.hasScope('trust')")
					.antMatchers("/photos/user/**").access("#oauth2.hasScope('trust')")					
					.antMatchers("/photos/**").access("#oauth2.hasScope('read') or (!#oauth2.isOAuth() and hasRole('ROLE_USER'))")
					.regexMatchers(HttpMethod.DELETE, "/oauth/users/([^/].*?)/tokens/.*")
						.access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('write')")
					.regexMatchers(HttpMethod.GET, "/oauth/clients/([^/].*?)/users/.*")
						.access("#oauth2.clientHasRole('ROLE_CLIENT') and (hasRole('ROLE_USER') or #oauth2.isClient()) and #oauth2.hasScope('read')")
					.regexMatchers(HttpMethod.GET, "/oauth/clients/.*")
						.access("#oauth2.clientHasRole('ROLE_CLIENT') and #oauth2.isClient() and #oauth2.hasScope('read')");
			// @formatter:on
		}
		
		JwtAccessTokenConverter tokenConverter(){
			JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
			jwtTokenEnhancer.setVerifier(new SignatureVerifier(){

				@Override
				public String algorithm() {
					return sigAlg;
				}

				@Override
				public void verify(byte[] content, byte[] signature) {
					try {
						KeyStore keystore = KeyStore.getInstance(storeType);
						keystore.load(new ClassPathResource(trustStore).getInputStream(), storepass.toCharArray());
						Certificate cert = keystore.getCertificate(trustKeyAlias);
						Signature sig = Signature.getInstance(algorithm());
						sig.initVerify(cert);
						sig.update(content);
						if(!sig.verify(signature)){
							throw new InvalidSignatureException("Signature did not match content");
						}
					} catch (KeyStoreException
							| NoSuchAlgorithmException | CertificateException
							| IOException | InvalidKeyException | SignatureException e) {
						log.error("", e);
					}
					
				}
				
			});
		
			return jwtTokenEnhancer;
		}
		
		@Bean
		TokenStore jwtTokenStore(){
			return new JwtTokenStore(tokenConverter());
		}
		
		@Bean
		ResourceServerTokenServices tokenServices(){
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setTokenStore(jwtTokenStore());
			return tokenServices;
		}
	}
	
	
	
	
}
