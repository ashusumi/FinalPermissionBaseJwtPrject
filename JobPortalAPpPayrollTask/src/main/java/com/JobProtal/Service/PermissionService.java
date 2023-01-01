package com.JobProtal.Service;

import java.util.List;

import com.JobProtal.Dto.PermissionDto;

public interface PermissionService {

	public List<PermissionDto> getAllPermission();

	public String deletePermission(Long id);

	String updatePermission(Long id, PermissionDto permission);

	String addPermission(PermissionDto permission);
}
