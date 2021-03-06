package org.AuthenticateServer.dao;

import java.util.Date;

import org.AuthenticateServer.config.TestConfig;
import org.auth.dao.UserRoleDao;
import org.business.models.UserRole;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class UserRoleDaoTest extends TestConfig {

	@Autowired
	private UserRoleDao userRoleDao;
	
	@Test
	public final void testFindByOwnerIdAndType() {
	}

	@Test
	public final void testSaveS() {
		UserRole userRole = new UserRole();
		userRole.setOwnerId(2l);
		userRole.setRoleId(1l);
		userRole.setType(UserRole.TYPE_USER);
		userRole.setCreateBy("junit");
		userRole.setCreateTime(new Date());
		userRoleDao.save(userRole);
		
		userRole = new UserRole();
		userRole.setOwnerId(2l);
		userRole.setRoleId(2l);
		userRole.setType(UserRole.TYPE_USER);
		userRole.setCreateBy("junit");
		userRole.setCreateTime(new Date());
		userRoleDao.save(userRole);
		
		userRole = new UserRole();
		userRole.setOwnerId(2l);
		userRole.setRoleId(3l);
		userRole.setType(UserRole.TYPE_USER);
		userRole.setCreateBy("junit");
		userRole.setCreateTime(new Date());
		userRoleDao.save(userRole);
		
		
	}
	
	@Test
	public final void testDelete() {
		userRoleDao.delete(3l);
	}

}
