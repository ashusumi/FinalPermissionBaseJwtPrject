package com.JobProtal.Dto;

import java.util.Set;

import com.JobProtal.Entity.Permission;

public class RoleDto {

	private Long id;
	private String roleName;
	private boolean enabled;
	
	private Set<Permission> permissions;

	public RoleDto() {
		super();
		// TODO Auto-generated constructor stub
	}



	public boolean isEnabled() {
		return enabled;
	}



	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}



	public RoleDto(Long id, String roleName, boolean enabled, Set<Permission> permissions) {
		super();
		this.id = id;
		this.roleName = roleName;
		this.enabled = enabled;
		this.permissions = permissions;
	}



	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getRoleName() {
		return roleName;
	}

	public void setRoleName(String roleName) {
		this.roleName = roleName;
	}

	public Set<Permission> getPermissions() {
		return permissions;
	}

	public void setPermissions(Set<Permission> permissions) {
		this.permissions = permissions;
	}
}
