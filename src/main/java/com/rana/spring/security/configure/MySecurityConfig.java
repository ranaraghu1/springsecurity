package com.rana.spring.security.configure;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.rana.spring.security.MyAuthenticationProvider;

@Configuration
public class MySecurityConfig extends WebSecurityConfigurerAdapter{
	
	@Autowired
	MyAuthenticationProvider myAutheticationProvider;
	
	/*
	 * @Override protected void configure(AuthenticationManagerBuilder auth) throws
	 * Exception {
	 * 
	 * BCryptPasswordEncoder passwordEncoder=new BCryptPasswordEncoder();
	 * InMemoryUserDetailsManager userDetailsService=new
	 * InMemoryUserDetailsManager(); UserDetails
	 * user=User.withUsername("raghu").password(passwordEncoder.encode("rana")).
	 * authorities("read").build(); userDetailsService.createUser(user);
	 * auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder);
	 * }
	 */
	
	
	 @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		 auth.authenticationProvider(myAutheticationProvider);
	 }
	 
	 
		  @Override protected void configure(HttpSecurity http) throws Exception {
		  http.httpBasic(); http.authorizeRequests().anyRequest().authenticated(); 
		  }
		

		/*
		 * @Override protected void configure(HttpSecurity http) throws Exception {
		 * http.formLogin();
		 * http.authorizeRequests().antMatchers("/hello").authenticated().anyRequest().
		 * denyAll(); }
		 */
		 
}
