package com.dgmf.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

// Provide Configurations for Spring IoC Container (ApplicationContext)
@Configuration
// Enable Web Security Features and Allows Customization
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // Tells Spring IoC Container (ApplicationContext) to Hold a Bean Based
    // the Below Configurations
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // Any Request Should Be Authenticated
        http.authorizeHttpRequests(
                requests -> requests
                        .anyRequest()
                        .authenticated()
        );
        // To Disable Cookies Management and Make API Stateless
        http.sessionManagement(
                session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );
        // We have Disabled Form-Based Authentication
        // http.formLogin(withDefaults());
        // Tells Spring Security to Use Basic Authentication (Alert Box)
        // with Username and Password
        http.httpBasic(withDefaults());

        // Returns an Object of SecurityFilterChain Type
        return http.build();
    }

    // In Memory Authentication
    // InMemoryUserDetailsManager ==> Implementation of UserDetailsService
    // Prefix {noop} ==> To Tell Spring this Password Should Be Stored as
    // Plain Text
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                .password("{noop}userPassword")
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password("{noop}adminPassword")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin); // Constructor
    }
}
