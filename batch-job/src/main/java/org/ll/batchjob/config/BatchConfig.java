package org.ll.batchjob.config;

import java.util.List;

import javax.sql.DataSource;

import org.business.models.Product;
import org.ll.batchjob.listener.JobCompletionNotificationListener;
import org.ll.batchjob.processor.ProductItemProcessor;
import org.springframework.batch.core.Job;
import org.springframework.batch.core.Step;
import org.springframework.batch.core.configuration.annotation.DefaultBatchConfigurer;
import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
import org.springframework.batch.core.configuration.annotation.JobBuilderFactory;
import org.springframework.batch.core.configuration.annotation.StepBuilderFactory;
import org.springframework.batch.core.launch.support.RunIdIncrementer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableBatchProcessing
public class BatchConfig extends DefaultBatchConfigurer {

	@Override
	public void setDataSource(DataSource dataSource) {
		// override to do not set datasource even if a datasource exist.
		// initialize will use a Map based JobRepository (instead of database)
	}

	@Autowired
	public JobBuilderFactory jobBuilderFactory;

	@Autowired
	public StepBuilderFactory stepBuilderFactory;

	@Autowired
	private ProductItemProcessor productItemProcessor;

	@Bean
	public Job importUserJob(JobCompletionNotificationListener listener,
			Step step1) {
		return jobBuilderFactory.get("importUserJob")
				.incrementer(new RunIdIncrementer()).listener(listener)
				.flow(step1)
				.end()
				.build();
	}

	@Bean
	public Step step1() {
		return stepBuilderFactory.get("step1")
				.<List<Product>, Integer> chunk(300)
				.reader(productItemProcessor)
				.processor(productItemProcessor)
				.writer(productItemProcessor)
				.build();
	}
}