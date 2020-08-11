package org.ll.batchjob.processor;
import java.util.List;

import org.business.models.Product;
import org.business.util.TimeUtil;
import org.ll.batchjob.dao.ProductDao;
import org.ll.batchjob.service.IndexService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.batch.item.ItemProcessor;
import org.springframework.batch.item.ItemReader;
import org.springframework.batch.item.ItemWriter;
import org.springframework.batch.item.NonTransientResourceException;
import org.springframework.batch.item.ParseException;
import org.springframework.batch.item.UnexpectedInputException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

@Service
public class ProductItemProcessor implements ItemReader<List<Product>>, ItemProcessor<List<Product>, Integer>, ItemWriter<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ProductItemProcessor.class);
    
  	@Autowired private ProductDao productDao; 
  
  	@Autowired private IndexService indexService;
  	
	@Override
	public List<Product> read() throws Exception, UnexpectedInputException,
			ParseException, NonTransientResourceException {
		indexService.search(TimeUtil.getCurrentTime())
		.flatMap(str -> {log.debug("str: [{}]", str); return Mono.just(str);})
		;
		
		return productDao.findByCreateTimeGreaterThan(org.business.util.TimeUtil.ORIGINAL_DATETIME);
	}
	
	@Override
	public Integer process(List<Product> items) throws Exception {
		log.info("process start");
		log.debug("items.size(): {}",  (items == null? 0 : items.size()));
		String startTime = TimeUtil.getCurrentTime();
		if(items != null && !items.isEmpty()){
			indexService.index("product", items);
		}
		String endTime = TimeUtil.getCurrentTime();
		log.debug("startTime: {}, endTime: {}, duration: {}ms", startTime, endTime, TimeUtil.getMilliSecondDuration(startTime, endTime));
		log.info("process end");
		return 1;
	}

	@Override
	public void write(List<? extends Integer> items) throws Exception {
		log.info("writer start");
		items.forEach(i -> log.debug("item rtn:" + i));
		log.info("writer complete");
	}

}