package com.JobProtal.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.JobProtal.Entity.Permission;

public interface PermissionRepository extends JpaRepository<Permission, Long> {

}
