package org.ll.batchjob.service;

import java.util.List;

import org.business.models.Product;
import org.ll.auth.annotation.feign.LLRequestBody;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

@FeignClient(name = "api-gateway", contextId="index", path = "/v1/search-service")
public interface IndexService {

	@PostMapping("/index") public String index(@LLRequestBody("index") String index, @LLRequestBody("models") List<Product> models);
	
	@DeleteMapping("/index") public String deleteIndex(@RequestParam("index") String index);
	
	@GetMapping("/search") public Mono<String> search(@RequestParam("time") String time);
}
