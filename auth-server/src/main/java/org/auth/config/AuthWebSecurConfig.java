package org.auth.config;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.Filter;

import org.auth.dao.UserDao;
import org.auth.dao.UserRoleDao;
import org.business.models.User;
import org.business.models.UserRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
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
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
public class AuthWebSecurConfig extends WebSecurityConfigurerAdapter {

	private final static Logger log = LoggerFactory.getLogger(AuthWebSecurConfig.class);
	

	@Configuration
	@EnableAuthorizationServer
	public static class AuthorizationServer extends AuthorizationServerConfigurerAdapter {

		@Value("${api.resourceID}")
		private String api_resource_id;
		
		@Value("${api.client}")
		private String client;
		
		@Value("${api.secret}")
		private String secret;
		
		@Autowired
		MultiGrantType grantTypegs;
		
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
		
		
		class MultiGrantType{
			private List<String> grantTypes;

			public List<String> getGrantTypes() {
				return grantTypes;
			}

			public void setGrantTypes(List<String> grantTypes) {
				this.grantTypes = grantTypes;
			}
		}
		
		@Bean
		@ConfigurationProperties("api")
		MultiGrantType grantTypegs(){
			return new MultiGrantType();
		}

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

			// @formatter:off
			clients.inMemory()
		            .withClient(client)
		            	.resourceIds(api_resource_id)
		            	.secret(secret)
		                .authorizedGrantTypes(grantTypegs.getGrantTypes().toArray(new String[grantTypegs.getGrantTypes().size()]))
		                .authorities("ROLE_CLIENT")
		                .scopes("read", "write")
		                .autoApprove(true)
		                .accessTokenValiditySeconds(600)
		                .refreshTokenValiditySeconds(900)
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
					KeyStoreKeyFactory keystore = new KeyStoreKeyFactory(new ClassPathResource(authKeyStore), storepass.toCharArray());
					PrivateKey privateKey = keystore.getKeyPair(keyAlias).getPrivate();
					try {
						Signature sig = Signature.getInstance(algorithm());
						sig.initSign(privateKey);
						sig.update(bytes);
						return sig.sign();
					} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
						e.printStackTrace();
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
			
			return new org.springframework.security.core.userdetails.User(username, user.getPassword(), roles);
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
