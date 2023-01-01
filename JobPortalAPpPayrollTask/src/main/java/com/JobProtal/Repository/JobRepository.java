package com.JobProtal.Repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.JobProtal.Entity.Job;

public interface JobRepository extends JpaRepository<Job, Long>{

}
