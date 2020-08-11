package org.auth.dao;

import org.auth.config.TestConfig;
import org.business.models.Role;
import org.business.util.TimeUtil;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class RoleDaoTest extends TestConfig {
	
	private final static Logger log = LoggerFactory.getLogger(RoleDaoTest.class);
	
	@Autowired
	RoleDao roleDao;
	
	@Autowired PasswordEncoder passwordEncoder;

	@Test
	public final void testSaveS() {
		Role role = new Role();
		role.setName("USER");
		role.setCreateBy(1l);
		role.setCreateTime(TimeUtil.getCurrentTime());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		role = new Role();
		role.setName("ADMIN");
		role.setCreateBy(1l);
		role.setCreateTime(TimeUtil.getCurrentTime());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		role = new Role();
		role.setName("API_USER");
		role.setCreateBy(1l);
		role.setCreateTime(TimeUtil.getCurrentTime());
		roleDao.save(role);
		log.debug("role.getId():" + role.getId());
		
		
	}
	
	@Test
	public final void testDelete() {
		roleDao.deleteById(1l);
		roleDao.deleteById(2l);
	}
	
	@Test
	public final void test(){
		log.debug("result:" + passwordEncoder.encode("secret"));
	}

}
