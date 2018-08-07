package org.ll.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;


@SpringBootApplication
@EnableZuulProxy
public class startGateway {
	public static void main(String[] args) {
	    SpringApplication.run(startGateway.class, args);
	  }
}
