package com.JobProtal.ServiceImpl;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.JobProtal.Dto.RegisteredDto;
import com.JobProtal.Dto.UserDto;
import com.JobProtal.Entity.Job;
import com.JobProtal.Entity.Role;
import com.JobProtal.Entity.User;
import com.JobProtal.Repository.JobRepository;
import com.JobProtal.Repository.RoleRepository;
import com.JobProtal.Repository.UserRepository;
import com.JobProtal.Service.UserService;

@Service
public class IUser implements UserService {

	@Autowired
	private UserRepository repo;

	@Autowired
	private RoleRepository rrepo;

	@Autowired
	private JobRepository jrepo;

	@Autowired
	private PasswordEncoder encoder;

	@Override
	public List<UserDto> getAllUser() {
		List<User> user = repo.findAll();
		List<UserDto> dto = new ArrayList<>();
		for (int i = 0; i < user.size(); i++) {
			UserDto dto2 = new UserDto();
			dto2.setId(user.get(i).getId());
			dto2.setUsername(user.get(i).getUsername());
			dto2.setEmail(user.get(i).getEmail());
			dto2.setFirstName(user.get(i).getFirstName());
			dto2.setLastName(user.get(i).getLastName());
			dto2.setIsactive(user.get(i).isActive());
			dto2.setPassword(user.get(i).getPassword());
			dto2.setRole(new HashSet<>(user.get(i).getRoles()));
			dto.add(dto2);

		}
		return dto;
	}

	@Override
	public String addUser(UserDto user) {
		User newUser = new User();
		long id = 1;
		Set<Role> Drole = new HashSet<>();
		Role roleD = rrepo.findById(id).orElse(null);
		Drole.add(roleD);
		List<User> users = new ArrayList<>();
		newUser.setUsername(user.getUsername());
		newUser.setEmail(user.getEmail());
		newUser.setFirstName(user.getFirstName());
		newUser.setLastName(user.getLastName());
		newUser.setActive(true);
		String encp = user.getPassword();
		newUser.setPassword(encoder.encode(encp));
		newUser.setRoles(Drole);
		users.add(newUser);
		repo.saveAll(users);
		return "User added";
	}

	@Override
	public String upadteUser(Long id, UserDto dto) {
		User user = repo.findById(id).orElse(null);
		user.setId(user.getId());
		user.setFirstName(dto.getFirstName());
		user.setLastName(dto.getLastName());
		user.setPassword(dto.getPassword());
		user.setUsername(dto.getUsername());
		user.setActive(dto.isIsactive());
		user.setRoles(new HashSet<>(dto.getRole()));
		repo.save(user);
		return "user updated";

	}

	@Override
	public String deleteId(Long id) {
		User user = repo.findById(id).orElse(null);
		repo.delete(user);
		return "deleted";
	}

	public void assignUserRole(Long userId, Long RoleId) {
		User user = repo.findById(userId).orElse(null);
		Role role = rrepo.findById(RoleId).orElse(null);
		Set<Role> userRole = user.getRoles();
		userRole.add(role);
		user.setRoles(userRole);
		repo.save(user);
	}

	@Override
	public String applyJob(String email, Long Jobid) {
		User user = repo.findByEmail(email).orElse(null);
		Job job = jrepo.findById(Jobid).orElse(null);
		Set<Job> userJob = user.getJobs();
		userJob.add(job);
		user.setJobs(userJob);
		repo.save(user);
		return "job applied";
	}

	@Override
	public List<RegisteredDto> getRegisteredUser() {
		List<User> user = repo.findAll();
		List<RegisteredDto> newDto = new ArrayList<>();
		for (int i = 0; i < user.size(); i++) {
			RegisteredDto reg = new RegisteredDto();
			reg.setEmail(user.get(i).getEmail());
			reg.setFirstName(user.get(i).getFirstName());
			reg.setLastName(user.get(i).getLastName());
			reg.setUsername(user.get(i).getUsername());
			newDto.add(reg);
		}
		return newDto;
	}
}
