package org.AuthenticateServer.dao;

import org.business.models.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserDao extends JpaRepository<User, Long>{
	
	public User findByUsername(String username);

}
