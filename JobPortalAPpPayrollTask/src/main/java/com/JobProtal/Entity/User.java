package com.JobProtal.Entity;

import java.io.Serializable;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinTable;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;

@Entity
@Table(name = "Users")
public class User implements Serializable{

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	@Column(name ="Id")
	private long id;
	
	@Column(name="FirstName")
	@NotBlank(message = "FirstName should not be Blank")
	private String FirstName;
	
	@Column(name = "LastName")
	@NotBlank(message = "LastName should not be Blank")
	private String lastName;
	
	@Column(name = "Email")
	@NotBlank(message = "Email shuold not be blank")
	private String email;
	
	@Column(name = "password")
	@NotEmpty(message = "password required")
	private String password;
	
	@Column(name="username")
	@NotEmpty(message = "user name required")
	private String username;
	
	@Column(name ="IsActive")
	private boolean isActive=true;
	
	@ManyToMany(cascade = CascadeType.MERGE, fetch = FetchType.EAGER)
	@JoinTable(name = "user_role", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles;

	@ManyToMany(cascade = CascadeType.MERGE,fetch = FetchType.EAGER)
	@JoinTable(name="user_job",joinColumns = @JoinColumn(name="user_id"),
	inverseJoinColumns = @JoinColumn(name="job_id"))
	private Set<Job> jobs;

	public User(long id, @NotBlank(message = "FirstName should not be Blank") String firstName,
			@NotBlank(message = "LastName should not be Blank") String lastName,
			@NotBlank(message = "Email shuold not be blank") String email,
			@NotEmpty(message = "password required") String password,
			@NotEmpty(message = "user name required") String username, boolean isActive, Set<Role> roles,
			Set<Job> jobs) {
		super();
		this.id = id;
		FirstName = firstName;
		this.lastName = lastName;
		this.email = email;
		this.password = password;
		this.username = username;
		this.isActive = isActive;
		this.roles = roles;
		this.jobs = jobs;
	}

	public User() {
		super();
		// TODO Auto-generated constructor stub
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getFirstName() {
		return FirstName;
	}

	public void setFirstName(String firstName) {
		FirstName = firstName;
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

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean isActive) {
		this.isActive = isActive;
	}

	public Set<Role> getRoles() {
		return roles;
	}

	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}

	public Set<Job> getJobs() {
		return jobs;
	}

	public void setJobs(Set<Job> jobs) {
		this.jobs = jobs;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", FirstName=" + FirstName + ", lastName=" + lastName + ", email=" + email
				+ ", password=" + password + ", username=" + username + ", isActive=" + isActive + ", roles=" + roles
				+ ", jobs=" + jobs + "]";
	}
	
	
	
}
