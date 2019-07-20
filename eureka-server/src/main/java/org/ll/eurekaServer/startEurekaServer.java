package org.ll.eurekaServer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.cloud.netflix.eureka.server.EnableEurekaServer;

@SpringBootApplication
@EnableEurekaServer
public class startEurekaServer 
	extends org.springframework.boot.web.support.SpringBootServletInitializer 
	{

	@Override
	protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
		return application.sources(startEurekaServer.class);
	}
	public static void main(String[] args){
		SpringApplication.run(startEurekaServer.class, args);
	}
}
