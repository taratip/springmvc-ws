package com.appsdeveloperblog.app.ws.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.SecretKey;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	public AuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		String header = request.getHeader(SecurityConstants.HEADER_STRING);

		if (header == null || !header.startsWith(SecurityConstants.TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);

	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {

		String authorizationHeader = request.getHeader(SecurityConstants.HEADER_STRING);

		if (authorizationHeader == null) {
			return null;
		}

		String token = authorizationHeader.replace(SecurityConstants.TOKEN_PREFIX, "");

		byte[] secretKeyBytes = Base64.getEncoder().encode(SecurityConstants.getTokenSecret().getBytes());
		SecretKey secretKey = Keys.hmacShaKeyFor(secretKeyBytes);

		JwtParser jwtParser = Jwts.parser()
                .verifyWith(secretKey)
                .build();

		Claims claims = jwtParser.parseSignedClaims(token).getPayload();
        String subject = (String) claims.get("sub");

		if (subject == null) {
			return null;
		}

		return new UsernamePasswordAuthenticationToken(subject, null, new ArrayList<>());

	}

}
