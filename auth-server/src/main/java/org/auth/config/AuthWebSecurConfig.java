package org.auth.config;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.auth.dao.UserDao;
import org.auth.dao.UserRoleDao;
import org.auth.model.Oauth2ClientDetailsProperties;
import org.business.models.User;
import org.business.models.UserRole;
import org.business.models.applysystem.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jwt.crypto.sign.Signer;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

@Configuration
@EnableWebSecurity
public class AuthWebSecurConfig extends WebSecurityConfigurerAdapter {

	private final static Logger log = LoggerFactory.getLogger(AuthWebSecurConfig.class);
	

	@Configuration
	@EnableAuthorizationServer
	public static class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

		@Value("${security.trustStore}")
		private String authKeyStore;
		
		@Value("${security.storepass}")
		private String storepass;
		
		@Value("${security.trustKeyAlias}")
		private String keyAlias;
		
		@Value("${security.storeType}")
		private String storeType;
		
		@Value("${security.sigAlg}")
		private String sigAlg;
		
		@Autowired
		private TokenStore tokenStore;

//		@Autowired
//		private UserApprovalHandler userApprovalHandler;

//		@Autowired
//		private AuthorizationCodeServices authorizationCodeServices;
		
		@Autowired
		@Qualifier("authenticationManager")
		private AuthenticationManager authenticationManager;
		
		@Bean
		@ConfigurationProperties("security.oauth2.clientDetails")
		Oauth2ClientDetailsProperties oauth2ClientDetailsProperties(){
			return new Oauth2ClientDetailsProperties();
		}
		
		InMemoryClientDetailsService inMemoryClientDetailsService(){
			InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
			Map<String, ClientDetails> clientDetailsStore = new HashMap<>();
			
			List<? extends ClientDetails> clients = oauth2ClientDetailsProperties().getClients();
			clients
				.stream()
				.forEach(detail -> clientDetailsStore.put(detail.getClientId(), detail))
				;
			clientDetailsService.setClientDetailsStore(clientDetailsStore );
			return clientDetailsService;
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

			// @formatter:off
			clients.inMemory()
					.clients(inMemoryClientDetailsService())
			;
			// @formatter:on
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints
					.tokenStore(tokenStore)
					.accessTokenConverter(tokenConverter())
//					.userApprovalHandler(userApprovalHandler)
					.authenticationManager(authenticationManager)
					;
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
			oauthServer.realm("sparklr2/client")
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("isAuthenticated()")
			;
		}
		
		
		
		@Bean
		JwtAccessTokenConverter tokenConverter(){
			JwtAccessTokenConverter jwtTokenEnhancer = new JwtAccessTokenConverter();
			jwtTokenEnhancer.setSigner(new Signer(){
				@Override
				public String algorithm() {
					return sigAlg;
				}

				@Override
				public byte[] sign(byte[] bytes) {
					if(log.isDebugEnabled()){
						log.debug("authKeyStore:" + authKeyStore);
						log.debug("storepass:" + storepass);
						log.debug("keyAlias:" + keyAlias);
					}
					try {
						KeyStoreKeyFactory keystore = new KeyStoreKeyFactory(new ClassPathResource(authKeyStore), storepass.toCharArray());
						if(log.isDebugEnabled()){
							log.debug("keystore:" + keystore);
						}
						PrivateKey privateKey = keystore.getKeyPair(keyAlias).getPrivate();
						if(log.isDebugEnabled()){
							log.debug("privateKey:" + privateKey);
						}
						Signature sig = Signature.getInstance(algorithm());
						if(log.isDebugEnabled()){
							log.debug("sig:" + sig);
						}
						sig.initSign(privateKey);
						sig.update(bytes);
						if(log.isDebugEnabled()){
							log.debug("sig done" );
						}
						return sig.sign();
					} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
						log.error("", e);
					}
					return bytes;
				}
				
			});
			return jwtTokenEnhancer;
		}
		
		@Bean
		TokenStore jwtTokenStore(){
			return new JwtTokenStore(tokenConverter());
		}
		
		@Bean
		DefaultTokenServices tokenServices(){
			DefaultTokenServices tokenServices = new DefaultTokenServices();
			tokenServices.setTokenStore(jwtTokenStore());
			tokenServices.setReuseRefreshToken(true);
			return tokenServices;
		}
		
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
        .authorizeRequests()
        .antMatchers("/login**", "/favicon.ico").permitAll()
        .anyRequest().hasAnyRole("API_USER", "ADMIN", "USER")
        .and()
        	.logout()
            	.logoutUrl("/logout")
                .logoutSuccessUrl("/login")
        .and()
        	.formLogin().permitAll()
//        .and()
//        	.csrf()
//                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
//                .disable()
//        	.addFilterAfter(new OAuth2AuthenticationProcessingFilter(), UsernamePasswordAuthenticationFilter.class)
        
        ;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth)
			throws Exception {
		auth
			.authenticationProvider(customAuthenticationProvider())
		;
	}
	
	@Bean
	UserDetailsService customUserDetailsService(){
		return new CustomUserDetailsService();
	}
	
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }
	
	class CustomUserDetailsService implements UserDetailsService {

		@Autowired
		private UserDao userDao;
		
		@Autowired
		private UserRoleDao userRoleDao;
		
		@Override
		public UserDetails loadUserByUsername(String username)
				throws UsernameNotFoundException {
			User user = userDao.findByUsername(username);
			List<GrantedAuthority> roles = null;
			if(user != null){
				List<UserRole> tmp = userRoleDao.findByOwnerIdAndType(user.getId(), UserRole.TYPE_USER); 
				if(tmp != null){
					roles = new ArrayList<>(tmp.size());
					for(UserRole role : tmp){
						roles.add(new SimpleGrantedAuthority("ROLE_" + role.getRole().getName().toUpperCase()));
					}
				}
			}
			if(log.isDebugEnabled()){
				
				log.debug("username:" + username + ", user:"+ user + ", roles:" + roles);
			}
			
			return new CustomUserDetails(user.getId(), username, user.getPassword(), roles);
		}

	}
	
	
	@Bean 
	PasswordEncoder bCryptPasswordEncoder(){
		return new BCryptPasswordEncoder();
	}
	
	@Bean
	AuthenticationProvider customAuthenticationProvider(){
		DaoAuthenticationProvider customAuthenticationProvider = new DaoAuthenticationProvider(){
			
			@Override
			protected void additionalAuthenticationChecks(
					UserDetails userDetails,
					UsernamePasswordAuthenticationToken authentication)
					throws AuthenticationException {
				authentication.getDetails();
				String username = authentication.getName();
				String password = (String) authentication.getCredentials();
				
				WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
				
				if(log.isDebugEnabled()){
					log.debug("username:" + username + ", password:" + password + ", userDetails.getPassword():" + userDetails.getPassword() + ", details:" + details + ", details.getClass():" + details.getClass());
				}
				
				if(!userDetails.isEnabled() 
						|| !bCryptPasswordEncoder().matches(password, userDetails.getPassword())
						){
					throw new BadCredentialsException("bad credentials:" + username);
				}
			}
			
		};
		customAuthenticationProvider.setUserDetailsService(customUserDetailsService());
		return customAuthenticationProvider;
	}

	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}
	
}
