package org.auth.dao;

import java.util.Date;

import org.auth.config.TestConfig;
import org.auth.dao.RoleDao;
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
		Role role = new Role();
		role.setName("USER");
		role.setCreateBy("junit");
		role.setCreateTime(new Date());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		role = new Role();
		role.setName("ADMIN");
		role.setCreateBy("junit");
		role.setCreateTime(new Date());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		role = new Role();
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
