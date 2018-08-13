package org.AuthenticateServer.dao;

import java.util.Date;

import org.AuthenticateServer.config.TestConfig;
import org.AuthenticateServer.service.impl.CustomUserDetailsServiceTest;
import org.business.models.Role;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class RoleDaoTest extends TestConfig {
	
	private final static Logger log = LoggerFactory.getLogger(RoleDaoTest.class);
	
	@Autowired
	RoleDao roleDao;

	@Test
	public final void testSaveS() {
//		Role role = new Role();
//		role.setName("USER");
//		role.setCreateBy("junit");
//		role.setCreateTime(new Date());
//		roleDao.save(role);
//		log.debug("role.getId():" + role.getId());
//		
//		Role role2 = new Role();
//		role2.setName("ADMIN");
//		role2.setCreateBy("junit");
//		role2.setCreateTime(new Date());
//		roleDao.save(role2);
//		log.debug("role2.getId():" + role2.getId());
		
		Role role = new Role();
		role.setName("API_USER");
		role.setCreateBy("junit");
		role.setCreateTime(new Date());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		
	}
	
	@Test
	public final void testDelete() {
		roleDao.delete(1l);
		roleDao.delete(2l);
	}
	
	

}
