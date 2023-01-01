package com.JobProtal.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.JobProtal.Entity.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{
	Role findByRoleName( String roleName);
}
