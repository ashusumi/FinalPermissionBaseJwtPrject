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

import com.JobProtal.Dto.PermissionDto;
import com.JobProtal.ServiceImpl.IPermission;

@RestController
@RequestMapping("/Permission")
public class PermissionController {

	@Autowired
	private IPermission permissionS;

	@PostMapping("/add")
	//@PreAuthorize("hasAuthority('ADD')")
	public String addPermission(@RequestBody PermissionDto permission) {
		permissionS.addPermission(permission);
		return "permission saved";
	}

	@GetMapping("/all")
	public List<PermissionDto> getALLPermission() {
		return permissionS.getAllPermission();
	}

	@PutMapping("/edit/{id}")
	public String updatePermission(@PathVariable Long id, @RequestBody PermissionDto permission) {

		permissionS.updatePermission(id, permission);
		return "permission edited";
	}

	@DeleteMapping("/delete/{id}")
	public String deletePermission(@PathVariable Long id) {
		permissionS.deletePermission(id);
		return "permission deleted";
	}
}
