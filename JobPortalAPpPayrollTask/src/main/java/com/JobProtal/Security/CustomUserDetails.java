package com.JobProtal.Security;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import com.JobProtal.Entity.Role;
import com.JobProtal.Entity.User;
import com.JobProtal.Repository.UserRepository;


@Component
public class CustomUserDetails implements UserDetailsService {

	@Autowired
	private UserRepository repository;
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		User user=repository.findByUsername(username);
		System.out.println(user);
		if(user==null) {
			throw new UsernameNotFoundException(username+"not found");
		}
		
//		CustomUser customUser=new CustomUser(user);
//		//System.out.println(customUser.getAuthorities());
//		System.out.println(customUser.getAuthorities());
//		return customUser;
		
		return new org.springframework.security.core.userdetails.User(user.getUsername(),user.getPassword(),getAuth(user));
	}
	
	private Collection<GrantedAuthority> getAuth(User user) {
		Set<GrantedAuthority> ga = new HashSet<>();
	
		for (Role role : user.getRoles()) {
			//ga.add(new SimpleGrantedAuthority(role.getRole()));

			for (com.JobProtal.Entity.Permission permission : role.getPermissions()) {
				ga.add(new SimpleGrantedAuthority(permission.getPermissionName()));

			}
		}
		System.out.println(ga);
		return ga;
	}

}
