package org.auth;

import static org.junit.Assert.fail;

import org.auth.config.TestConfig;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;


@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment= WebEnvironment.NONE, 
properties={})
public class Test  extends TestConfig{

	private static final Logger log = LoggerFactory.getLogger(Test.class);
	@Autowired private PasswordEncoder passwordEncoder;
	
	@org.junit.Test
	public final void test() {
		log.info(passwordEncoder.encode("secret"));
	}

}
