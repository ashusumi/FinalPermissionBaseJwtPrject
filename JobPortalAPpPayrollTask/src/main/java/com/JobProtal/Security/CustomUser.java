//package com.JobProtal.Security;
//
//import java.util.ArrayList;
//import java.util.Collection;
//import java.util.HashSet;
//import java.util.Set;
//
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Component;
//
//import com.JobProtal.Entity.Permission;
//import com.JobProtal.Entity.Role;
//import com.JobProtal.Entity.User;
//
//
//public class CustomUser implements UserDetails {
//
//	/**
//	 * 
//	 */
//	private static final long serialVersionUID = 1L;
//	private User user;
//
//	public CustomUser(User user) {
//		super();
//		this.user = user;
//	}
//
////	public CustomUser() {
////		super();
////		// TODO Auto-generated constructor stub
////	}
//
//	@Override
//	public Collection<? extends GrantedAuthority> getAuthorities() {
//		Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
//		Set<Role> roles = user.getRoles();
//		for (Role role : roles) {
//			for (Permission permission : role.getPermissions())
//				authorities.add(new SimpleGrantedAuthority("ROLE_"+permission.getPermissionName()));
//			System.out.println(authorities);
//		}
//		return authorities;
//	}
//
//	@Override
//	public String getPassword() {
//		// TODO Auto-generated method stub
//		return user.getPassword();
//	}
//
//	@Override
//	public String getUsername() {
//		// TODO Auto-generated method stub
//		return user.getUsername();
//	}
//
//	@Override
//	public boolean isAccountNonExpired() {
//		// TODO Auto-generated method stub
//		return true;
//	}
//
//	@Override
//	public boolean isAccountNonLocked() {
//		// TODO Auto-generated method stub
//		return true;
//	}
//
//	@Override
//	public boolean isCredentialsNonExpired() {
//		// TODO Auto-generated method stub
//		return true;
//	}
//
//	@Override
//	public boolean isEnabled() {
//		// TODO Auto-generated method stub
//		return true;
//	}
//
//}
