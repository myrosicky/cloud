package org.ll.batchjob.dao;

import java.util.List;

import org.business.models.Product;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ProductDao extends JpaRepository<Product, Long> {

	public List<Product> findByCreateTimeGreaterThan(String startTime);
	
}
