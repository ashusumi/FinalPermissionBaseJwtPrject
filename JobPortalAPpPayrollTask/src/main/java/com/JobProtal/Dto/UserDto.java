package com.JobProtal.Dto;

import java.io.Serializable;
import java.util.Set;

import com.JobProtal.Entity.Role;
import com.JobProtal.Entity.User;
import com.fasterxml.jackson.annotation.JsonIgnore;

public class UserDto implements Serializable{

	@JsonIgnore
	private User user;
	private static final long serialVersionUID = 1L;
	private Long id;
	private String username;
	private String email;
	private String password;
	private String firstName;
	private String lastName;
	private boolean isactive;
	
	Set<Role> role;
	
	
	public UserDto() {
		super();
	}
	public String getFirstName() {
		return firstName;
	}
	public UserDto(User user, Long id, String username, String email, String password, String firstName,
				String lastName, boolean isactive, Set<Role> role) {
			super();
			this.user = user;
			this.id = id;
			this.username = username;
			this.email = email;
			this.password = password;
			this.firstName = firstName;
			this.lastName = lastName;
			this.isactive = isactive;
			this.role = role;
		}

	public void setFirstName(String firstName) {
		this.firstName = firstName;
	}
	public String getLastName() {
		return lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public boolean isIsactive() {
		return isactive;
	}
	public void setIsactive(boolean isactive) {
		this.isactive = isactive;
	}
	public String getUsername() {
		return username;
	}
	public void setUsername(String username) {
		this.username = username;
	}
	public String getEmail() {
		return email;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public Set<Role> getRole() {
		return role;
	}
	public void setRole(Set<Role> role) {
		this.role = role;
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	
	
}

