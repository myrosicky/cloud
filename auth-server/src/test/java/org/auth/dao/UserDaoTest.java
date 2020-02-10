package org.auth.dao;

import org.auth.config.TestConfig;
import org.auth.util.TimeUtil;
import org.business.models.User;
import org.business.models.applysystem.Dictionary;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class UserDaoTest extends TestConfig {
	
	private final static Logger log = LoggerFactory.getLogger(UserDaoTest.class);
	
	@Autowired
	UserDao userDao;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Test
	public final void testFindByUsername() {
		User user = userDao.findByUsername("");
	}

	@Test
	public final void testSaveIterableOfS() {
		User user = new User();
		log.info("TimeUtil.getCurrentTime():" + TimeUtil.getCurrentTime());
		try {
			user.setLoginLastTime(TimeUtil.getCurrentTime());
		} catch (Exception e) {
			e.printStackTrace();
		}
		user.setPassword(new BCryptPasswordEncoder().encode("llismoon"));
		user.setRegisterDate(TimeUtil.getCurrentTime());
		user.setGeneral_ip("127.0.0.1");
		user.setUsername("u");
		user.setDeleted(Dictionary.Deleted.FALSE.toString());
		user.setCategory("");
		user.setRemark("");
		userDao.save(user);
	}
	
	@Test
	public final void testUpdate() {
		log.debug("passwordEncoder:" + passwordEncoder);
		User user = userDao.findByUsername("u");
		user.setPassword(passwordEncoder.encode("p"));
		user.setLoginLastTime(TimeUtil.getCurrentTime());
		userDao.save(user);
	}
	
	@Test
	public final void testPasswordMatch() {
		log.debug("passwordEncoder:" + passwordEncoder);
		User user = userDao.findByUsername("u");
		log.debug("password match:" + passwordEncoder.matches("p", user.getPassword()));
	}
	
	@Test
	public final void testDelete() {
		userDao.deleteById(1l);
	}
	
}
