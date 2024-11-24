package com.appsdeveloperblog.app.ws.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import com.appsdeveloperblog.app.ws.service.UserService;

@Configuration
@EnableWebSecurity
public class WebSecurity {
	private final UserService userDetailsService;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	public WebSecurity(UserService userDetailsService, BCryptPasswordEncoder bCryptPasswordEncoder) {
		this.userDetailsService = userDetailsService;
		this.bCryptPasswordEncoder = bCryptPasswordEncoder;
	}
	
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    	AuthenticationManagerBuilder authenticationManagerBuilder = 
    		http.getSharedObject(AuthenticationManagerBuilder.class);
    	
		authenticationManagerBuilder
			.userDetailsService(userDetailsService)
			.passwordEncoder(bCryptPasswordEncoder);
		
		AuthenticationManager authenticationManager = authenticationManagerBuilder.build();
		
		AuthenticationFilter authenticationFilter = new AuthenticationFilter(authenticationManager);
		authenticationFilter.setFilterProcessesUrl("/users/login");
		
        http.csrf((csrf) -> csrf.disable())
            .authorizeHttpRequests((authz) -> {
				try {
					authz
						.requestMatchers(HttpMethod.POST, SecurityConstants.SIGN_UP_URL)
						.permitAll()
						.anyRequest().authenticated()
						.and()
						.authenticationManager(authenticationManager)
						.addFilter(authenticationFilter)
						.addFilter(new AuthorizationFilter(authenticationManager))
						.sessionManagement()
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
				} catch (Exception e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
            );
        return http.build();
    }
}
