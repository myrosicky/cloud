package org.ll.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
//@EnableZuulProxy
public class startGateway {
	public static void main(String[] args) {
	    SpringApplication.run(startGateway.class, args);
	  }
}
