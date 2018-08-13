package org.AuthenticateServer.service.impl;

import org.AuthenticateServer.config.TestConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class CustomUserDetailsServiceTest extends TestConfig {

	private final static Logger log = LoggerFactory.getLogger(CustomUserDetailsServiceTest.class);
	
	@Autowired
	private CustomUserDetailsService customUserDetailsService;
	
	@Test
	public final void testLoadUserByUsername() {
		String username = "u";
		UserDetails  userDetails  = customUserDetailsService.loadUserByUsername(username);
		log.debug("userDetails:" + userDetails);
	}

}
