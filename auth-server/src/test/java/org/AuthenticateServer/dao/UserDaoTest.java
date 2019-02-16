package org.AuthenticateServer.dao;

import java.util.Date;

import org.AuthenticateServer.config.TestConfig;
import org.auth.dao.UserDao;
import org.business.models.User;
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
		user.setLoginLastTime(new Date());
		user.setPassword(new BCryptPasswordEncoder().encode("llismoon"));
		user.setregisterDate(new Date());
		user.setRemark("no remark");
		user.setGeneral_ip("127.0.0.1");
		user.setUsername("u");
		user.setValid(1);
		user.setCategory("");
		user.setLoginLastTime(new Date());
		user.setregisterDate(new Date());
		user.setRemark("");
		userDao.save(user);
	}
	
	@Test
	public final void testUpdate() {
		log.debug("passwordEncoder:" + passwordEncoder);
		User user = userDao.findByUsername("u");
		user.setPassword(passwordEncoder.encode("p"));
		user.setLoginLastTime(new Date());
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
		userDao.delete(1l);
	}
	
}
