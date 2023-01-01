package com.JobProtal.Controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.JobProtal.Dto.RoleDto;
import com.JobProtal.Entity.Role;
import com.JobProtal.Repository.RoleRepository;
import com.JobProtal.ServiceImpl.IRole;

@RestController
@RequestMapping("/Role")
public class RoleController {

	@Autowired
	private IRole Irole;

	@Autowired
	private RoleRepository repo;

	@GetMapping("/all")
	//@PreAuthorize("hasAuthority('ADD')")
	public List<RoleDto> getAllRole() {
		return Irole.getAllRole();
	}

	@GetMapping("/admin")
	public List<Role> getRole() {
		return repo.findAll();
	}

	@PostMapping("/add")
	//@PreAuthorize("hasAuthority('ADD')")
	public String addRole(@RequestBody RoleDto role) {
		Irole.addRole(role);
		return "role added";
	}

	@DeleteMapping("/delete/{id}")
	public String deleteRole(@PathVariable Long id) {
		Irole.deleteRole(id);
		return "role deleted";
	}

	@PutMapping("/edit/{id}")
	public String update(@PathVariable Long id, @RequestBody RoleDto role) {
		Irole.updateRole(id, role);
		return "role edited";
	}
}
