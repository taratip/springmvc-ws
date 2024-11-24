package com.appsdeveloperblog.app.ws.security;

import org.springframework.core.env.Environment;

import com.appsdeveloperblog.app.ws.SpringApplicationContext;

public class SecurityConstants {
	public static final long EXPIRATION_TIME = 864000000; // 10 days
	public static final long PASSWORD_RESET_EXPIRATION_TIME = 3600000; // 1 hour
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	public static final String SIGN_UP_URL = "/users";
	public static final String TOKEN_SECRET = "5GYyYDSdIFyUAGjAb1yFdJ6SR4E8V1iMqklGwJlvsOYd4JTWSuvzcZ08caWTRpnB";

	public static String getTokenSecret() {
		Environment appProperties = (Environment) SpringApplicationContext.getBean("environment");
		return appProperties.getProperty("tokenSecret");
	}

}
