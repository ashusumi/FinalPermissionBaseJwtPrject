package com.JobProtal.Entity;

import java.io.Serializable;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "Permission")
public class Permission implements Serializable{

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name = "Id")
	private long id;
	
	@Column(name = "PermissionName")
	@NotBlank(message = "PermissionName should not be Blank")
	private String permissionName;
	
	@Column(name = "IsActive")
	private boolean isActive;
	
	@JsonIgnore
	@ManyToMany(mappedBy = "permissions",cascade = CascadeType.MERGE)
	private Set<Role> roles;

	public Permission(long id, @NotBlank(message = "PermissionName should not be Blank") String permissionName,
			boolean isActive) {
		super();
		this.id = id;
		this.permissionName = permissionName;
		this.isActive = isActive;
	}

	public Permission() {
		super();
		// TODO Auto-generated constructor stub
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getPermissionName() {
		return permissionName;
	}

	public void setPermissionName(String permissionName) {
		this.permissionName = permissionName;
	}

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean isActive) {
		this.isActive = isActive;
	}
	
	

}
