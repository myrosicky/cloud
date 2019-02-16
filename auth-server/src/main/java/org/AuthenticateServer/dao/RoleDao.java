package org.AuthenticateServer.dao;

import org.business.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoleDao extends JpaRepository<Role, Long>{

}
