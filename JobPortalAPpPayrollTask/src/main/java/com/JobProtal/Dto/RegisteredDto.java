package com.JobProtal.Dto;

import java.io.Serializable;

public class RegisteredDto implements Serializable{

	private static final long serialVersionUID = 1L;
	private String username;
	private String firstName;
	private String lastName;
	private String email;

	public RegisteredDto() {
		super();
		// TODO Auto-generated constructor stub
	}

	public RegisteredDto(String username, String firstName, String lastName, String email) {
		super();
		this.username = username;
		this.firstName = firstName;
		this.lastName = lastName;
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getFirstName() {
		return firstName;
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

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
}
