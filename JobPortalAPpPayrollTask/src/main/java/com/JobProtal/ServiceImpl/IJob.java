package com.JobProtal.ServiceImpl;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.JobProtal.Dto.JobDto;
import com.JobProtal.Entity.Job;
import com.JobProtal.Repository.JobRepository;
import com.JobProtal.Service.JobService;

@Service
public class IJob implements JobService {

	@Autowired
	private JobRepository repo;

	@Override
	public List<JobDto> getAllJobs() {
		List<Job> jobs = repo.findAll();
		List<JobDto> dto = new ArrayList<>();
		for (int i = 0; i < jobs.size(); i++) {
			JobDto dto1 = new JobDto();
			dto1.setId(jobs.get(i).getId());
			dto1.setJobName(jobs.get(i).getJobName());
			dto1.setEmail(jobs.get(i).getEmail());
			dto1.setJobDescription(jobs.get(i).getJobDescription());
			dto1.setCompanyName(jobs.get(i).getCompanyName());
			dto1.setLocation(jobs.get(i).getLocation());
			dto1.setActive(true);
			dto.add(dto1);
		}

		return dto;
	}

	@Override
	public String addJobs(JobDto jobs) {
		Job job = new Job();
		job.setJobName(jobs.getJobName());
		job.setJobDescription(jobs.getJobDescription());
		job.setCompanyName(jobs.getCompanyName());
		job.setEmail(jobs.getEmail());
		job.setLocation(jobs.getLocation());
		job.setActive(true);
		repo.save(job);
		return "job added";
	}

	@Override
	public String updateJob(JobDto jobs, Long id) {
		Job job = repo.findById(id).orElse(null);
		job.setJobName(jobs.getJobName());
		job.setJobDescription(jobs.getJobDescription());
		job.setCompanyName(jobs.getCompanyName());
		job.setEmail(jobs.getEmail());
		job.setLocation(jobs.getLocation());
		job.setActive(true);
		repo.save(job);

		return "job updated";
	}

	@Override
	public String deleteJobs(Long id) {
		Job job = repo.findById(id).orElse(null);
		repo.delete(job);
		return "job deleted";
	}
}
