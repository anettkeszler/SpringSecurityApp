package com.example.security.security;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    private final PasswordEncoder passwordEncoder;

    public SecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*") // whitelist specific urls--> visible for everyone
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    // how you retrieve your users from user database
    public UserDetailsService userDetailsService() {

        UserDetails anna = User.builder()
                .username("anna")
                .password(passwordEncoder.encode("password"))
                .roles("STUDENT") // ROLE_STUDENT
                .build();

        UserDetails netti = User.builder()
                .username("netti")
                .password(passwordEncoder.encode("password"))
                .roles("ADMIN") // ROLE_ADMIN
                .build();

        return new InMemoryUserDetailsManager(
                anna,
                netti
        );
    }
}
