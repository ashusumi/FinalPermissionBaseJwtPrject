package com.JobProtal.Dto;

public class JobDto {

	private Long id;
	private String jobName;
	private String jobDescription;
	private String companyName;
	private boolean isActive;
	private String location;
	private String email;
	public JobDto(Long id, String jobName, String jobDescription, String companyName, boolean isActive, String location,
			String email) {
		super();
		this.id = id;
		this.jobName = jobName;
		this.jobDescription = jobDescription;
		this.companyName = companyName;
		this.isActive = isActive;
		this.location = location;
		this.email = email;
	}
	public JobDto() {
		super();
		// TODO Auto-generated constructor stub
	}
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
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
	public boolean isActive() {
		return isActive;
	}
	public void setActive(boolean isActive) {
		this.isActive = isActive;
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
}
