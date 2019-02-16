package org.AuthenticateServer.config;

import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment= WebEnvironment.DEFINED_PORT, 
properties={
		"eureka.client.register-with-eureka=false",
		"eureka.client.fetch-registry=false"
})
@TestConfiguration
public class TestConfig {

}
