package org.zerock.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.extern.java.Log;

@EnableWebSecurity
@Log
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private ZerockDetailsService zerockService;

	 @Bean
	  public PasswordEncoder passwordEncoder() {
	      return new BCryptPasswordEncoder();
	  }

	
	@Override
	protected void configure(HttpSecurity http) throws Exception {

		log.info("security config..............");

		http.authorizeRequests().antMatchers("/guest/**").permitAll();

		http.authorizeRequests().antMatchers("/manager/**").hasRole("MANAGER");
		
		http.formLogin().loginPage("/login");
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {

		log.info("build Auth global........");
        auth.userDetailsService(zerockService).passwordEncoder(passwordEncoder());
	}



}
