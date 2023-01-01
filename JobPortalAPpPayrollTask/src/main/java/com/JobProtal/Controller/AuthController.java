
package com.JobProtal.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.JobProtal.JwtModel.AuthToken;
import com.JobProtal.JwtModel.LoginDto;
import com.JobProtal.Security.TokenProvider;

@CrossOrigin(origins = "*",maxAge = 3600)
@RestController
@RequestMapping("/Token")
public class AuthController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private TokenProvider provider;
	
	@Autowired
	private UserDetailsService detailsService;
	
	@PostMapping("/generate")
	public ResponseEntity<?> register(@RequestBody LoginDto dto){
		final Authentication authentication=authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(dto.getUsername(), dto.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		final String token=provider.generateToken(authentication);
		return ResponseEntity.ok(new AuthToken(token));
	}
}
