package org.auth.provider;

import java.util.ArrayList;
import java.util.List;

import org.auth.dao.UserDao;
import org.auth.dao.UserRoleDao;
import org.business.models.User;
import org.business.models.UserRole;
import org.business.models.applysystem.CustomUserDetails;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

@Component("userDetailsService")
@Primary
public class CustomUserDetailsService implements UserDetailsService {
	
	private final static Logger log = LoggerFactory
			.getLogger(CustomUserDetailsService.class);

	@Autowired
	private UserDao userDao;

	@Autowired
	private UserRoleDao userRoleDao;

	@Override
	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		User user = userDao.findByUsername(username);
		List<GrantedAuthority> roles = null;
		if (user != null) {
			List<UserRole> tmp = userRoleDao.findByOwnerIdAndType(user.getId(),
					UserRole.TYPE_USER);
			if (tmp != null) {
				roles = new ArrayList<>(tmp.size());
				for (UserRole role : tmp) {
					roles.add(new SimpleGrantedAuthority("ROLE_"
							+ role.getRole().getName().toUpperCase()));
				}
			}
		}
		if (log.isDebugEnabled()) {

			log.debug("username:" + username + ", user:" + user + ", roles:"
					+ roles);
		}

		return new CustomUserDetails(user.getId(), username,
				user.getPassword(), roles);
	}

}