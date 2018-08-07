package org.ll.gateway.context;

import org.ll.gateway.filter.PreFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class WebContext {

	 @Bean
	  public PreFilter simpleFilter() {
	    return new PreFilter();
	  }
}
