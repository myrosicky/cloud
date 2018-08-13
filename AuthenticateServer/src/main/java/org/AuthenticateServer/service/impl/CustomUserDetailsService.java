package org.AuthenticateServer.service.impl;

import java.util.ArrayList;
import java.util.List;

import org.AuthenticateServer.dao.UserDao;
import org.AuthenticateServer.dao.UserRoleDao;
import org.business.models.User;
import org.business.models.UserRole;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CustomUserDetailsService implements UserDetailsService {

	private final static Logger log = LoggerFactory.getLogger(CustomUserDetailsService.class);
	
	@Autowired
	private UserDao userDao;
	
	@Autowired
	private UserRoleDao userRoleDao;
	
	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		User user = userDao.findByUsername(username);
		List<GrantedAuthority> roles = null;
		if(user != null){
			List<UserRole> tmp = userRoleDao.findByOwnerIdAndType(user.getId(), UserRole.TYPE_USER); 
			if(tmp != null){
				roles = new ArrayList<>(tmp.size());
				for(UserRole role : tmp){
					roles.add(new SimpleGrantedAuthority("ROLE_" + role.getRole().getName().toUpperCase()));
				}
			}
		}
		if(log.isDebugEnabled()){
			log.debug("roles:" + roles);
		}
		
		return new org.springframework.security.core.userdetails.User(username, user.getPassword(), roles);
	}

}
