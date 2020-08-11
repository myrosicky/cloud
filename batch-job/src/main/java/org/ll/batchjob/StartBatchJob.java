package org.ll.batchjob;

import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;

/**
 * Hello world!
 *
 */
@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class})
public class StartBatchJob 
{
    public static void main( String[] args )
    {
        new SpringApplicationBuilder()
        .web(WebApplicationType.NONE)
        .sources(StartBatchJob.class)
        .build()
        .run(args)
        ;
    }
}
