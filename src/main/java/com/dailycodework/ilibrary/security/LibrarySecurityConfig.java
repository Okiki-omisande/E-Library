package com.dailycodework.ilibrary.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class LibrarySecurityConfig {
    private static final  String[] SECURED_URLS = {"/books/**"};
    private static final  String[] UNSECURED_URLS = {"/books/all*","books/book/{id}","/users/**"};

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http.csrf().disable()
                .authorizeHttpRequests()
                .requestMatchers(UNSECURED_URLS)
                .permitAll()
                .and()
                .authorizeHttpRequests()
                .requestMatchers(SECURED_URLS)
                .hasAuthority("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic()
                .and().build();
    }
}
