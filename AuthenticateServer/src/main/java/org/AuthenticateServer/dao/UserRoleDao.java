package org.AuthenticateServer.dao;

import java.util.List;

import org.business.models.UserRole;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRoleDao extends JpaRepository<UserRole, Long>{

	public List<UserRole> findByOwnerIdAndType(Long ownerId, Integer type);
}
