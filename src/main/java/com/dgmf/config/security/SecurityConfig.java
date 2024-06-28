package com.dgmf.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

// Provide Configurations for Spring IoC Container (ApplicationContext)
@Configuration
// Enable Web Security Features and Allows Customization
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    // With AutoConfiguration (H2 in application.properties File), Spring
    // will Automatically Inject the Datasource (H2)
    @Autowired
    private DataSource dataSource;

    // Tells Spring IoC Container (ApplicationContext) to Hold a Bean Based
    // the Below Configurations
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // Any Request Should Be Authenticated
        http.authorizeHttpRequests(
                requests -> requests
                        // Disable Spring Security for H2 InMemory DB
                        .requestMatchers("/h2-console/**").permitAll()
                        .anyRequest().authenticated()
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
        // For Http Headers, allows Frame Options for the Same Origins
        http.headers(headers -> headers.frameOptions(
                HeadersConfigurer.FrameOptionsConfig::sameOrigin
            )
        );
        http.csrf(AbstractHttpConfigurer::disable);
        // Returns an Object of SecurityFilterChain Type
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // In Memory Authentication
    // InMemoryUserDetailsManager ==> Implementation of UserDetailsService
    // Prefix {noop} ==> To Tell Spring this Password Should Be Stored as
    // Plain Text
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user")
                // .password("{noop}user") ==> Plain Text Storage
                .password(passwordEncoder().encode("user"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                // .password("{noop}admin") ==> Plain Text Storage
                .password(passwordEncoder().encode("admin"))
                .roles("ADMIN")
                .build();

        // Set up the Datasource
        JdbcUserDetailsManager jdbcUserDetailsManager =
                new JdbcUserDetailsManager(dataSource);
        jdbcUserDetailsManager.createUser(user);
        jdbcUserDetailsManager.createUser(admin);

        // return new InMemoryUserDetailsManager(user, admin); // Constructor
        return jdbcUserDetailsManager;
    }
}
