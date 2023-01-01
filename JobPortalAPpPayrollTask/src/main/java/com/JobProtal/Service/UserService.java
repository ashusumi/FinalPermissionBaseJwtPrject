package com.JobProtal.Service;

import java.util.List;

import com.JobProtal.Dto.RegisteredDto;
import com.JobProtal.Dto.UserDto;

public interface UserService {

	public List<UserDto> getAllUser();

	public String deleteId(Long id);

	String addUser(UserDto user);

	String upadteUser(Long id, UserDto dto);
	
	public List<RegisteredDto> getRegisteredUser();
	
	public String applyJob(String email,Long Jobid);
}
