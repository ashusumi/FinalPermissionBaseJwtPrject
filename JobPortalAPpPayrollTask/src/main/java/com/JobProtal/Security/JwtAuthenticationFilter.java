package com.JobProtal.Security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;

import static com.JobProtal.JwtModel.Constants.HEADER_STRING;
import static com.JobProtal.JwtModel.Constants.TOKEN_PREFIX;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	@Autowired
	private UserDetailsService detailsService;

	@Autowired
	private TokenProvider provider;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader(HEADER_STRING);
		String username = null;
		String authToken = null;
		if(header!=null && header.startsWith(TOKEN_PREFIX)) {
			authToken=header.replace(TOKEN_PREFIX,"");
			try {
				username=provider.getUsernameFromToken(authToken);
			} catch (IllegalArgumentException e) {
				logger.error("an error occured getting username"+e);
			}catch (ExpiredJwtException e) {
				logger.error("token expired"+e);
			}catch (SignatureException e) {
				logger.error("signature error"+e);
			}
			
		}else {
			logger.warn("token not started with Bearer");
		}
		if (username!=null&& SecurityContextHolder.getContext().getAuthentication()==null) {
			UserDetails details=detailsService.loadUserByUsername(username);
			if(provider.validateToken(authToken, details)) {
				UsernamePasswordAuthenticationToken authenticationToken=provider.getAuthentication(authToken, SecurityContextHolder.getContext().getAuthentication(), details);
				authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				logger.info("authenticated user "+username+" ,setting security context");
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			}
		}
		filterChain.doFilter(request, response);
	}

}
