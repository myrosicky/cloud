package org.auth.provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

@Component
public class DBAuthenticationProvider extends DaoAuthenticationProvider{
				
	private final static Logger log = LoggerFactory.getLogger(DBAuthenticationProvider.class);
	
	@Autowired private PasswordEncoder passwordEncoder;
	
	@Autowired private UserDetailsService userDetailsService;
	
	@Override
	protected void doAfterPropertiesSet() throws Exception {
		setUserDetailsService(userDetailsService);
		super.doAfterPropertiesSet();
	}

	@Override
	protected void additionalAuthenticationChecks(
			UserDetails userDetails,
			UsernamePasswordAuthenticationToken authentication)
			throws AuthenticationException {
		String username = authentication.getName();
		String password = (String) authentication.getCredentials();
		
		WebAuthenticationDetails details = (WebAuthenticationDetails)authentication.getDetails();
		
		if(log.isDebugEnabled()){
			log.debug("passwordEncoder:" + passwordEncoder);
			log.debug("userDetailsService:" + userDetailsService);
			log.debug("username:" + username + ", password:" + password + ", userDetails.getPassword():" + userDetails.getPassword() + ", details:" + details + ", details.getClass():" + details.getClass());
		}
		
		if(!userDetails.isEnabled() 
				|| !passwordEncoder.matches(password, userDetails.getPassword())
				){
			throw new BadCredentialsException("bad credentials:" + username);
		}
	}
	
	
				
			
}

