package com.JobProtal.Service;

import java.util.List;

import com.JobProtal.Dto.JobDto;

public interface JobService {

	public List<JobDto> getAllJobs();

	public String addJobs(JobDto jobs);

	public String updateJob(JobDto jobs, Long id);

	public String deleteJobs(Long id);
}
