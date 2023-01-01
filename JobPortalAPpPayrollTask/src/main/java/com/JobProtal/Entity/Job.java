package com.JobProtal.Entity;

import java.io.Serializable;
import java.util.Set;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotBlank;

@Entity
@Table(name="Job")
public class Job implements Serializable{
	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	
	@Column(name = "Id")
	private long id;
	
	@Column(name = "JobName")
	@NotBlank(message = "JobName should not be Blank")
	private String jobName;

	@Column(name = "JobDescription")
	@NotBlank(message = "JobDescription should not be Blank")
	private String jobDescription;
	@Column(name = "CompapyName")
	@NotBlank(message = "CompanyName should not be Blank")
	private String companyName;
	
	@Column(name = "Location")
	@NotBlank(message = "Location should not be Blank")
	private String location;
	
	@Column(name = "Email")
	@NotBlank(message = "Email should not be Blank")
	private String email;
	
	@Column(name = "IsActive")
	private boolean isActive;
	
	@ManyToMany(mappedBy = "jobs")
	private Set<User> user;

	public Job(long id, @NotBlank(message = "JobName should not be Blank") String jobName,
			@NotBlank(message = "JobDescription should not be Blank") String jobDescription,
			@NotBlank(message = "CompanyName should not be Blank") String companyName,
			@NotBlank(message = "Location should not be Blank") String location,
			@NotBlank(message = "Email should not be Blank") String email, boolean isActive) {
		super();
		this.id = id;
		this.jobName = jobName;
		this.jobDescription = jobDescription;
		this.companyName = companyName;
		this.location = location;
		this.email = email;
		this.isActive = isActive;
	}

	public Job() {
		super();
		// TODO Auto-generated constructor stub
	}

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getJobName() {
		return jobName;
	}

	public void setJobName(String jobName) {
		this.jobName = jobName;
	}

	public String getJobDescription() {
		return jobDescription;
	}

	public void setJobDescription(String jobDescription) {
		this.jobDescription = jobDescription;
	}

	public String getCompanyName() {
		return companyName;
	}

	public void setCompanyName(String companyName) {
		this.companyName = companyName;
	}

	public String getLocation() {
		return location;
	}

	public void setLocation(String location) {
		this.location = location;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public boolean isActive() {
		return isActive;
	}

	public void setActive(boolean isActive) {
		this.isActive = isActive;
	}
	
	
	
	
	
	

	
	
	

	

	
	
	
	
	
	

}
