package com.JobProtal.Service;

import java.util.List;

import com.JobProtal.Dto.RoleDto;

public interface RoleService {

	public List<RoleDto> getAllRole();

	// public String addRole(Role role);

	public String deleteRole(Long id);

	String updateRole(Long id, RoleDto role);

	String addRole(RoleDto role);
}
