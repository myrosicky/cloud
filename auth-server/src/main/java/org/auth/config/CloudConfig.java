package org.auth.config;

import java.util.Properties;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.config.java.AbstractCloudConfig;
//import org.springframework.cloud.config.java.AbstractCloudConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

@Configuration
@Profile("cloud")
class CloudConfig 
	extends AbstractCloudConfig 
	{
	
	private static final Logger log = LoggerFactory.getLogger(CloudConfig.class);
	
    @Bean
    public DataSource inventoryDataSource() {
        return connectionFactory().dataSource("instance1");
   }
    
    @Bean
    public Properties cloudProperties() {
         return properties();
    }
    
}
