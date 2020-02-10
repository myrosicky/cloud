package org.ll.gateway.config;

import org.springframework.cloud.netflix.zuul.filters.discovery.PatternServiceRouteMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RibbonConfig {

	@Bean
	public PatternServiceRouteMapper serviceRouteMapper(){
		// api application name: api-v1 to v1/api 
		return new PatternServiceRouteMapper(
				 "(?<name>^.+)-(?<version>v.+$)",
		        "${version}/${name}"
		);
	} 
}
