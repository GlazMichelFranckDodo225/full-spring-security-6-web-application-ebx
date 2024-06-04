package com.dgmf.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

// Provide Configurations for Spring IoC Container (ApplicationContext)
@Configuration
// Enable Web Security Features and Allows Customization
@EnableWebSecurity
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
}
