package org.auth.config;

import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment= WebEnvironment.DEFINED_PORT, 
properties={
		"eureka.client.register-with-eureka=true",
		"eureka.client.fetch-registry=true",
		"spring.application.name=auth-server",
		"spring.cloud.config.uri: ${CONFIG_SERVER_URL:http://localhost:8888}"
})
@TestConfiguration
public class TestConfig {

}
