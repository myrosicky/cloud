package org.auth.config;

import java.security.KeyPair;
import java.security.Principal;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

//@Configuration
//@Order(100)
public class AuthReactiveSecurConfig extends WebSecurityConfigurerAdapter {

	private final static Logger log = LoggerFactory.getLogger(AuthReactiveSecurConfig.class);
	
}
